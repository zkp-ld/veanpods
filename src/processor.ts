import type * as RDF from '@rdfjs/types';
import { BbsTermwiseSignatureProof2021 } from '@zkp-ld/rdf-signatures-bbs';
import jsonld from 'jsonld';
import { customAlphabet } from 'nanoid';
import { type Quadstore } from 'quadstore';
import { type Engine } from 'quadstore-comunica';
import { type DataFactory } from 'rdf-data-factory';
import sparqljs from 'sparqljs';
import { Anonymizer } from './anonymizer.js';
import { customLoader } from './data/index.js';
import {
  type InternalQueryResult,
  type JsonResults,
  type VerifiablePresentation,
  type ZkTriplePattern,
  type RevealedCredential,
} from './types';
import {
  addBnodePrefix,
  entriesToMap,
  genJsonResults,
  getCredentialMetadata,
  getProofsId,
  isWildcard,
  isZkObject,
  isZkPredicate,
  isZkSubject,
  parseQuery,
  streamToArray,
} from './utils.js';

// built-in JSON-LD contexts and sample VCs
const documentLoader = customLoader;

// ** constants ** //
const VP_KEY_IN_JSON_RESULTS = 'vp';
const VC_GRAPH_VAR_LENGTH = 20;
const vcGraphVarPrefixGenerator = customAlphabet(
  'abcdefghijklmnopqrstuvwxyz',
  VC_GRAPH_VAR_LENGTH
);
const PROOF = 'https://w3id.org/security#proof';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const VC_TYPE = 'https://www.w3.org/2018/credentials#VerifiableCredential';
const CONTEXTS = [
  'https://www.w3.org/2018/credentials/v1',
  'https://zkp-ld.org/bbs-termwise-2021.jsonld',
  'https://schema.org',
] as unknown as jsonld.ContextDefinition;
const VC_FRAME = {
  '@context': CONTEXTS,
  type: 'VerifiableCredential',
  proof: {}, // explicitly required otherwise `sec:proof` is used instead
};
const VP_TEMPLATE: VerifiablePresentation = {
  '@context': CONTEXTS,
  type: 'VerifiablePresentation',
  verifiableCredential: [],
};

/**
 * Parse zk-SPARQL query and return JSON results with verifiable presentations
 *
 * @param query - zk-SPARQL query
 * @param store - quadstore where verifiable credentials are stored
 * @param df - RDF/JS DataFactory
 * @param engine - SPARQL engine attached to the quadstore
 * @returns - JSON results or error object
 */
export const processQuery = async (
  query: string,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine
): Promise<JsonResults | { error: string }> => {
  // 1. parse zk-SPARQL query and execute SELECT on internal quadstore
  //    to get extended solutions
  const internalQueryResult = await executeInternalQueries(
    query,
    store,
    df,
    engine
  );
  if ('error' in internalQueryResult) {
    return internalQueryResult;
  }
  const { revealedSolutions, revealedVariables, revealedCredentialsArray } =
    internalQueryResult;

  // 2. generate VPs
  const vps = await generateVP(revealedCredentialsArray, df);
  if ('error' in vps) {
    return vps;
  }

  // 3. add VPs (or VCs) to each corresponding solutions
  const revealedSolutionWithVPs = revealedSolutions.map((revealedSolution, i) =>
    revealedSolution.set(
      VP_KEY_IN_JSON_RESULTS,
      df.literal(`${JSON.stringify(vps[i], null, 2)}`)
    )
  );
  revealedVariables.push(VP_KEY_IN_JSON_RESULTS);

  return genJsonResults(revealedVariables, revealedSolutionWithVPs);
};

/**
 * execute internal SPARQL queries to get extended solutions and associated VCs
 *
 * @param query - zk-SPARQL query
 * @param store - quadstore where verifiable credentials are stored
 * @param df - RDF/JS DataFactory
 * @param engine - SPARQL engine attached to the quadstore
 * @returns - internal query result including extended solutions, required (revealed) variables, revealed credentials, and anon to term map
 */
const executeInternalQueries = async (
  query: string,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine
): Promise<InternalQueryResult | { error: string }> => {
  // parse zk-SPARQL query
  const parsedQuery = parseQuery(query);
  if ('error' in parsedQuery) {
    return parsedQuery;
  }

  // assign a VC Graph Variable to each triple pattern in BGP
  const vcGraphVarPrefix = vcGraphVarPrefixGenerator();
  const bgpWithVcGraphVar: Array<[ZkTriplePattern, string]> =
    parsedQuery.bgp.map((triplePattern, i) => [
      triplePattern,
      `${vcGraphVarPrefix}${i}`,
    ]);

  // run extended SPARQL queries on the quadstore to get extended solutions
  const extendedSolutions = await getExtendedSolutions(
    bgpWithVcGraphVar,
    parsedQuery.notBgps,
    parsedQuery.prefixes,
    df,
    engine
  );

  // extract revealed variables from extended solution
  let revealedVariables: string[];
  if (isWildcard(parsedQuery.vars)) {
    revealedVariables =
      extendedSolutions.length === 0
        ? ['']
        : [...extendedSolutions[0].keys()]
            .map((v) => v.value)
            .filter((v) => !v.startsWith(vcGraphVarPrefix));
  } else {
    revealedVariables = parsedQuery.vars.map((v) => v.value);
  }

  // remove unrevealed bindings from extended solutions
  const revealedSolutions = extendedSolutions.map((extendedSolution) =>
    extendedSolution.filter((_, key) => revealedVariables.includes(key.value))
  );

  const revealedCredentialsArray = await Promise.all(
    extendedSolutions.map(
      async (extendedSolution) =>
        await getRevealedCredentials(
          extendedSolution,
          bgpWithVcGraphVar,
          parsedQuery.vars,
          store,
          df,
          engine
        )
    )
  );

  return {
    revealedSolutions,
    revealedVariables,
    revealedCredentialsArray,
  };
};

/**
 * get extended SPARQL solutions, which are SPARQL solutions
 * with _names of graphs_ where each input BGP triples is included
 *
 * @param parsedQuery - parsed zk-SPARQL query
 * @param df - RDF/JS DataFactory
 * @param engine - SPARQL engine attached to the quadstore
 * @returns - extended SPARQL solutions
 */
const getExtendedSolutions = async (
  bgpWithVcGraphVar: Array<[ZkTriplePattern, string]>,
  notBgps: sparqljs.Pattern[],
  prefixes: Record<string, string>,
  df: DataFactory<RDF.Quad>,
  engine: Engine
): Promise<RDF.Bindings[]> => {
  // construct an extended graph patterns based on BGP
  const extendedGraphPatterns: sparqljs.GraphPattern[] = bgpWithVcGraphVar.map(
    ([triplePattern, vcGraphVar]) => ({
      type: 'graph',
      name: df.variable(vcGraphVar),
      patterns: [
        {
          type: 'bgp',
          triples: [triplePattern],
        },
      ],
    })
  );

  // concat extended graph patterns and original not-BGPs (e.g., FILTER)
  const where = notBgps.concat(extendedGraphPatterns);

  // construct an extended SPARQL query
  const extendedQuery: sparqljs.SelectQuery = {
    type: 'query',
    queryType: 'SELECT',
    distinct: true,
    variables: [new sparqljs.Wildcard()],
    prefixes,
    where,
  };

  // execute extended query and get extended solutions
  const generator = new sparqljs.Generator();
  const generatedQuery = generator.stringify(extendedQuery);
  const bindingsStream = await engine.queryBindings(generatedQuery, {
    unionDefaultGraph: true, // extended query should be matched for all the VC graphs
  });
  const extendedSolutions = await streamToArray(bindingsStream);

  return extendedSolutions;
};

const getRevealedCredentials = async (
  extendedSolution: RDF.Bindings,
  bgpWithVcGraphVar: Array<[ZkTriplePattern, string]>,
  vars: [sparqljs.Wildcard] | RDF.Variable[],
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine
): Promise<RevealedCredential[]> => {
  const anonymizer = new Anonymizer(df);

  const anonymizedQuadWithVcGraphId = bgpWithVcGraphVar
    .map(([triplePattern, vcGraphVar]): [RDF.Quad, string] | undefined => {
      const anonymizedQuad = getAnonymizedQuad(
        triplePattern,
        extendedSolution,
        vars,
        anonymizer,
        df
      );
      const vcGraphId = extendedSolution.get(vcGraphVar)?.value;
      if (anonymizedQuad === undefined || vcGraphId === undefined) {
        return undefined;
      }

      return [anonymizedQuad, vcGraphId];
    })
    .filter((v): v is NonNullable<[RDF.Quad, string]> => v !== undefined);

  const revealedSubgraphs = entriesToMap(
    anonymizedQuadWithVcGraphId.map(([anonymizedQuad, vcGraphId]) => [
      vcGraphId,
      anonymizedQuad,
    ])
  );

  const revealedCredential = await constructRevealedCredentials(
    revealedSubgraphs,
    store,
    df,
    engine,
    anonymizer
  );

  return revealedCredential;
};

const getAnonymizedQuad = (
  triple: ZkTriplePattern,
  extendedSolution: RDF.Bindings,
  vars: [sparqljs.Wildcard] | RDF.Variable[],
  anonymizer: Anonymizer,
  df: DataFactory<RDF.Quad>
): RDF.Quad | undefined => {
  let subject: RDF.Term | undefined;
  if (triple.subject.termType !== 'Variable') {
    subject = triple.subject;
  } else if (vars.some((v) => v.value === triple.subject.value)) {
    subject = extendedSolution.get(triple.subject);
  } else {
    const val = extendedSolution.get(triple.subject);
    if (val !== undefined && isZkSubject(val)) {
      subject = anonymizer.anonymize(val);
    }
  }

  let predicate: RDF.Term | undefined;
  if (triple.predicate.termType !== 'Variable') {
    predicate = triple.predicate;
  } else if (vars.some((v) => v.value === triple.predicate.value)) {
    predicate = extendedSolution.get(triple.predicate);
  } else {
    const val = extendedSolution.get(triple.predicate);
    if (val !== undefined && isZkPredicate(val)) {
      predicate = anonymizer.anonymize(val);
    }
  }

  let object: RDF.Term | undefined;
  if (triple.object.termType !== 'Variable') {
    object = triple.object;
  } else if (vars.some((v) => v.value === triple.object.value)) {
    object = extendedSolution.get(triple.object);
  } else {
    const val = extendedSolution.get(triple.object);
    if (val !== undefined && isZkObject(val)) {
      object = anonymizer.anonymizeObject(val);
    }
  }

  const graph = df.defaultGraph();

  if (
    subject !== undefined &&
    isZkSubject(subject) &&
    predicate !== undefined &&
    isZkPredicate(predicate) &&
    object !== undefined &&
    isZkObject(object)
  ) {
    return df.quad(subject, predicate, object, graph);
  } else {
    return undefined;
  }
};

// get `revealedCreds`
const constructRevealedCredentials = async (
  revealedSubgraphs: Map<string, RDF.Quad[]>,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine,
  anonymizer: Anonymizer
): Promise<RevealedCredential[]> => {
  const revealedCreds = new Array<RevealedCredential>();
  for (const [graphIri, quads] of revealedSubgraphs) {
    // get a stored VC including revealed subgraph (quads)
    const vc = await store.get({
      graph: df.namedNode(graphIri),
    });
    // remove graph IRI from VC, which is only valid in the internal quadstore
    const vcDocument = vc.items.map((quad) =>
      df.quad(quad.subject, quad.predicate, quad.object)
    );

    // get associated proofs
    const vcProofs = await Promise.all(
      (
        await getProofsId(graphIri, engine)
      ).flatMap(async (proofId) => {
        if (proofId === undefined) {
          return [];
        }
        const proof = await store.get({
          graph: df.namedNode(proofId.value),
        });

        return proof.items;
      })
    );

    // get credential metadata
    const vcMetadata =
      (await getCredentialMetadata(graphIri, df, store, engine)) ?? [];

    // get anonymized credential by adding metadata to anonymized quads
    const anonymizedMetadata = vcMetadata.map((quad) => {
      const subject = isZkSubject(quad.subject)
        ? anonymizer.get(quad.subject)
        : quad.subject;
      const predicate = isZkPredicate(quad.predicate)
        ? anonymizer.get(quad.predicate)
        : quad.predicate;
      const object = isZkObject(quad.object)
        ? anonymizer.getObject(quad.object)
        : quad.object;

      return df.quad(
        subject !== undefined ? subject : quad.subject,
        predicate !== undefined ? predicate : quad.predicate,
        object !== undefined ? object : quad.object,
        df.defaultGraph()
      );
    });
    const anonymizedDoc =
      vcMetadata === undefined ? quads : quads.concat(anonymizedMetadata);

    revealedCreds.push({
      document: vcDocument,
      proofs: vcProofs,
      anonymizedDoc,
      anonToTerm: anonymizer.anonToTerm,
    });
  }

  return revealedCreds;
};

const generateVP = async (
  revealedCredentialsArray: RevealedCredential[][],
  df: DataFactory<RDF.Quad>
): Promise<VerifiablePresentation[] | { error: string }> => {
  const vps: VerifiablePresentation[] = [];
  for (const revealedCredentials of revealedCredentialsArray) {
    // run BBS+
    const inputDocuments = revealedCredentials.map(
      ({ document, proofs, anonymizedDoc, anonToTerm }) => ({
        document: document.filter((quad) => quad.predicate.value !== PROOF), // document without `proof` predicate
        proofs,
        revealedDocument: anonymizedDoc.filter(
          (quad) => quad.predicate.value !== PROOF
        ), // document without `proof` predicate
        anonToTerm,
      })
    );
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
    });
    const derivedProofs = await suite.deriveProofMultiRDF({
      inputDocuments,
      documentLoader,
    });

    // serialize derived VCs as JSON-LD documents
    const derivedVcs = [];
    for (const { document, proofs } of derivedProofs) {
      // connect document and proofs
      const vc = document.find(
        (quad) =>
          quad.predicate.value === RDF_TYPE && quad.object.value === VC_TYPE
      );
      if (vc === undefined) {
        return { error: 'a stored VC does not have Identifier' };
      }
      const credentialId = vc.subject;
      const proofGraphs: RDF.Quad[][] = [];
      for (const proof of proofs) {
        const proofGraphId = df.blankNode();
        const proofGraph = proof.map((quad) =>
          df.quad(quad.subject, quad.predicate, quad.object, proofGraphId)
        );
        proofGraphs.push(proofGraph);
        document.push(df.quad(credentialId, df.namedNode(PROOF), proofGraphId));
      }
      const cred = document.concat(proofGraphs.flat());
      // add bnode prefix `_:` to blank node ids
      const credWithBnodePrefix = addBnodePrefix(cred);
      const credJson = await jsonld.fromRDF(credWithBnodePrefix);
      // to compact JSON-LD
      const credJsonCompact = await jsonld.compact(credJson, CONTEXTS, {
        documentLoader,
      });
      // shape it to be a VC
      const derivedVc = await jsonld.frame(credJsonCompact, VC_FRAME, {
        documentLoader,
      });
      derivedVcs.push(derivedVc);
    }

    // serialize VP
    const vp = { ...VP_TEMPLATE };
    vp.verifiableCredential = derivedVcs;
    vps.push(vp);
  }

  return vps;
};
