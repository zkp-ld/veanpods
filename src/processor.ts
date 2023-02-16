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
  type RevealedData,
  type JsonResults,
  type VerifiablePresentation,
  type ZkTriplePattern,
  type VpSource,
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
  const revealedData = await getRevealedData(query, store, df, engine);
  if ('error' in revealedData) {
    return revealedData;
  }
  const { revealedVariables, revealedSolutions, vpSourcesArray } = revealedData;

  // 2. generate VPs
  const vps = await Promise.all(
    vpSourcesArray.map(async (vpSources) => await generateVP(vpSources, df))
  );

  // 3. add VPs to each revealed solutions
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
 * get revealed solutions and associated VCs by running internal query
 *
 * @param query - zk-SPARQL query
 * @param store - quadstore where verifiable credentials are stored
 * @param df - RDF/JS DataFactory
 * @param engine - SPARQL engine attached to the quadstore
 * @returns - internal query result including revealed variables, revealed solutions, and sources for generating VP
 */
const getRevealedData = async (
  query: string,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine
): Promise<RevealedData | { error: string }> => {
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

  // get VCs from quadstore and identify revealed subgraphs
  const vpSourcesArray = await Promise.all(
    extendedSolutions.map(
      async (extendedSolution) =>
        await getVpSources(
          extendedSolution,
          bgpWithVcGraphVar,
          revealedVariables,
          store,
          df,
          engine
        )
    )
  );

  // remove unrevealed bindings from extended solutions
  const revealedSolutions = extendedSolutions.map((extendedSolution) =>
    extendedSolution.filter((_, key) => revealedVariables.includes(key.value))
  );

  if (revealedSolutions.length !== vpSourcesArray.length) {
    return { error: 'internal query error' };
  }

  return {
    revealedVariables,
    revealedSolutions,
    vpSourcesArray,
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

  // TODO: sort solutions

  return extendedSolutions;
};

/**
 * get source data to generate VP
 *
 * @param extendedSolution - extended SPARQL solution
 * @param bgpWithVcGraphVar - triple pattern with VC Graph variable
 * @param revealedVariables - variables to be revealed
 * @param store - quadstore where verifiable credentials are stored
 * @param df - RDF/JS DataFactory
 * @param engine - SPARQL engine attached to the quadstore
 * @returns - source data to generate VP, i.e., VCs (document and proofs), anonymized documents, and de-anonymization map
 */
const getVpSources = async (
  extendedSolution: RDF.Bindings,
  bgpWithVcGraphVar: Array<[ZkTriplePattern, string]>,
  revealedVariables: string[],
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine
): Promise<VpSource[]> => {
  const anonymizer = new Anonymizer(df);

  const anonymizedQuadWithVcGraphId = bgpWithVcGraphVar
    .map(([triplePattern, vcGraphVar]): [RDF.Quad, string] | undefined => {
      const anonymizedQuad = getAnonymizedQuad(
        triplePattern,
        extendedSolution,
        revealedVariables,
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

  const vpSources = await Promise.all(
    [...revealedSubgraphs.entries()].map(
      async ([vcGraphId, revealedSubgraph]) =>
        await constructVpSource(
          vcGraphId,
          revealedSubgraph,
          store,
          df,
          engine,
          anonymizer
        )
    )
  );

  return vpSources;
};

const getAnonymizedQuad = (
  triplePattern: ZkTriplePattern,
  extendedSolution: RDF.Bindings,
  revealedVariables: string[],
  anonymizer: Anonymizer,
  df: DataFactory<RDF.Quad>
): RDF.Quad | undefined => {
  let subject: RDF.Term | undefined;
  if (triplePattern.subject.termType !== 'Variable') {
    subject = triplePattern.subject;
  } else if (revealedVariables.some((v) => v === triplePattern.subject.value)) {
    subject = extendedSolution.get(triplePattern.subject);
  } else {
    const val = extendedSolution.get(triplePattern.subject);
    if (val !== undefined && isZkSubject(val)) {
      subject = anonymizer.anonymize(val);
    }
  }

  let predicate: RDF.Term | undefined;
  if (triplePattern.predicate.termType !== 'Variable') {
    predicate = triplePattern.predicate;
  } else if (
    revealedVariables.some((v) => v === triplePattern.predicate.value)
  ) {
    predicate = extendedSolution.get(triplePattern.predicate);
  } else {
    const val = extendedSolution.get(triplePattern.predicate);
    if (val !== undefined && isZkPredicate(val)) {
      predicate = anonymizer.anonymize(val);
    }
  }

  let object: RDF.Term | undefined;
  if (triplePattern.object.termType !== 'Variable') {
    object = triplePattern.object;
  } else if (revealedVariables.some((v) => v === triplePattern.object.value)) {
    object = extendedSolution.get(triplePattern.object);
  } else {
    const val = extendedSolution.get(triplePattern.object);
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

const constructVpSource = async (
  vcGraphId: string,
  revealedSubgraph: RDF.Quad[],
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine,
  anonymizer: Anonymizer
): Promise<VpSource> => {
  // get a stored VC including revealed subgraph (quads)
  const { vcDocument, vcProofs } = await getVerifiableCredential(
    vcGraphId,
    store,
    df,
    engine
  );

  // get credential metadata
  const vcMetadata =
    (await getCredentialMetadata(vcGraphId, df, store, engine)) ?? [];

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
  const anonymizedDocument =
    vcMetadata === undefined
      ? revealedSubgraph
      : revealedSubgraph.concat(anonymizedMetadata);

  return {
    vcDocument,
    vcProofs,
    anonymizedDocument,
    deanonMap: anonymizer.deanonMap,
  };
};

const getVerifiableCredential = async (
  vcGraphId: string,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine
): Promise<{ vcDocument: RDF.Quad[]; vcProofs: RDF.Quad[][] }> => {
  // get a stored VC including revealed subgraph (quads)
  const vc = await store.get({
    graph: df.namedNode(vcGraphId),
  });
  // remove graph IRI from VC, which is only valid in the internal quadstore
  // TODO: remove data copy
  const vcDocument = vc.items.map((quad) =>
    df.quad(quad.subject, quad.predicate, quad.object)
  );

  // get associated proofs
  const vcProofs = await Promise.all(
    (
      await getProofsId(vcGraphId, engine)
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

  return { vcDocument, vcProofs };
};

const generateVP = async (
  vpSources: VpSource[],
  df: DataFactory<RDF.Quad>
): Promise<VerifiablePresentation | { error: string }> => {
  // run BBS+
  const inputDocuments = vpSources.map(
    ({ vcDocument, vcProofs, anonymizedDocument, deanonMap }) => ({
      document: vcDocument.filter((quad) => quad.predicate.value !== PROOF), // document without `proof` predicate
      proofs: vcProofs,
      revealedDocument: anonymizedDocument.filter(
        (quad) => quad.predicate.value !== PROOF
      ), // document without `proof` predicate
      anonToTerm: deanonMap,
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

  return vp;
};
