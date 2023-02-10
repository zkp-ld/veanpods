import type * as RDF from '@rdfjs/types';
import { BbsTermwiseSignatureProof2021 } from '@zkp-ld/rdf-signatures-bbs';
import jsonld from 'jsonld';
import { customAlphabet } from 'nanoid';
import { type Quadstore } from 'quadstore';
import { type Engine } from 'quadstore-comunica';
import { type DataFactory } from 'rdf-data-factory';
import sparqljs from 'sparqljs';
import { anonymizeQuad, Anonymizer } from './anonymizer.js';
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
  const { revealedSolutions, jsonVars, revealedCredsArray } =
    internalQueryResult;

  // 2. generate VPs
  const vps = await generateVP(revealedCredsArray, df);
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

  return genJsonResults(jsonVars, revealedSolutionWithVPs);
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

  // generate VC Graph Variables corresponding to each triple patterns in BGP
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

  const revealedCredsArray = await Promise.all(
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

  // remove unrevealed bindings from extended solutions
  const varNames = parsedQuery.vars.map((v) => v.value);
  const revealedSolutions = isWildcard(parsedQuery.vars)
    ? extendedSolutions
    : extendedSolutions.map((extendedSolution) =>
        extendedSolution.filter((_, key) => varNames.includes(key.value))
      );

  // construct vars for Query Results JSON Format
  let jsonVars: string[];
  if (isWildcard(parsedQuery.vars)) {
    // SELECT * WHERE {...}
    jsonVars =
      extendedSolutions.length >= 1
        ? [...extendedSolutions[0].keys()].map((k) => k.value)
        : [''];
  } else {
    // SELECT ?s ?p ?o WHERE {...}
    jsonVars = parsedQuery.vars.map((v) => v.value);
  }

  // add 'vp' to vars
  jsonVars.push(VP_KEY_IN_JSON_RESULTS);

  return {
    revealedSolutions,
    jsonVars,
    revealedCredsArray,
  };
};

const getRevealedCredentials = async (
  extendedSolution: RDF.Bindings,
  bgpWithVcGraphVar: Array<[ZkTriplePattern, string]>,
  vars: [sparqljs.Wildcard] | RDF.Variable[],
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine
): Promise<Map<string, RevealedCredential>> => {
  const vcGraphIdToTriplePatterns = identifyVcs(
    extendedSolution,
    bgpWithVcGraphVar
  );

  const anonymizer = new Anonymizer(df);

  const revealedQuads = getRevealedQuads(
    vcGraphIdToTriplePatterns,
    extendedSolution,
    vars,
    df,
    anonymizer
  );

  const revealedCredential = await getRevealedCreds(
    revealedQuads,
    store,
    df,
    engine,
    anonymizer
  );

  return revealedCredential;
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

/**
 * Return `graphIriToBgpTriple` from extended solution and graphVarToBgpTriple
 *
 * @param extendedSolution - extended SPARQL solution
 * @param bgpWithVcGraphVar - pairs of each triple pattern in BGP and its corresponding VC Graph Variable
 * @returns - a map from graph IRI to BGP triple with input extended solution
 *
 * @remarks
 * ## Examples
 *
 * extendedSolution (graph part only):
 * ```json
 * { // ... omitted SPARQL solution ...,
 *   "ggggg0": "http://example.org/g0",
 *   "ggggg1": "http://example.org/g1",
 *   "ggggg2": "http://example.org/g0" }
 * ```
 *
 * bgpWithVcGraphVar
 * ```json
 * [ [ (:s0 :p0 :o0), "ggggg0" ],
 *   [ (:s1 :p1 :o1), "ggggg1" ],
 *   [ (:s2 :p2 :o2), "ggggg2" ] ]
 * ```
 *
 * vcGraphIdAndTriplepattern:
 * ```json
 * [ [ "http://example.org/g0", (:s0 :p0 :o0) ],
 *   [ "http://example.org/g1", (:s1 :p1 :o1) ],
 *   [ "http://example.org/g0", (:s2 :p2 :o2) ] ]
 * ```
 *
 * vcGraphIdToTriplePatterns:
 * ```json
 * { "http://example.org/g0": [ (:s0 :p0 :o0), (:s2 :p2 :o2) ],
 *   "http://example.org/g1": [ (:s1 :p1 :o1 ) ] }
 * ```
 */
const identifyVcs = (
  extendedSolution: RDF.Bindings,
  bgpWithVcGraphVar: Array<[ZkTriplePattern, string]>
): Map<string, ZkTriplePattern[]> => {
  const vcGraphIdAndTriplePattern: Array<[string, ZkTriplePattern]> = [];
  for (const [triplePattern, vcGraphVar] of bgpWithVcGraphVar) {
    const uri = extendedSolution.get(vcGraphVar);
    if (uri === undefined || uri.termType !== 'NamedNode') continue;
    vcGraphIdAndTriplePattern.push([uri.value, triplePattern]);
  }
  const vcGraphIdToTriplePatterns = entriesToMap(vcGraphIdAndTriplePattern);

  return vcGraphIdToTriplePatterns;
};

// get `revealedQuads`
const getRevealedQuads = (
  vcGraphIdToTriplePatterns: Map<string, ZkTriplePattern[]>,
  bindings: RDF.Bindings,
  vars: sparqljs.VariableTerm[] | [sparqljs.Wildcard],
  df: DataFactory<RDF.Quad>,
  anonymizer: Anonymizer
): Map<string, RDF.Quad[]> => {
  const result = new Map<string, RDF.Quad[]>();
  for (const [
    vcGraphId,
    triplePatterns,
  ] of vcGraphIdToTriplePatterns.entries()) {
    const revealedQuads = triplePatterns.flatMap((triple) => {
      const subject =
        triple.subject.termType === 'Variable'
          ? bindings.get(triple.subject)
          : triple.subject;
      const predicate =
        triple.predicate.termType === 'Variable'
          ? bindings.get(triple.predicate)
          : triple.predicate;
      const object =
        triple.object.termType === 'Variable'
          ? bindings.get(triple.object)
          : triple.object;
      const graph = df.defaultGraph();
      if (
        subject !== undefined &&
        isZkSubject(subject) &&
        predicate !== undefined &&
        isZkPredicate(predicate) &&
        object !== undefined &&
        isZkObject(object)
      ) {
        return [df.quad(subject, predicate, object, graph)];
      } else {
        return [];
      }
    });
    const anonymizedQuads = isWildcard(vars)
      ? revealedQuads.map((quad) => df.fromQuad(quad)) // deep copy
      : anonymizeQuad(triplePatterns, vars, bindings, df, anonymizer);
    result.set(vcGraphId, anonymizedQuads);
  }

  return result;
};

// get `revealedCreds`
const getRevealedCreds = async (
  revealedQuads: Map<string, RDF.Quad[]>,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine,
  anonymizer: Anonymizer
): Promise<Map<string, RevealedCredential>> => {
  const revealedCreds = new Map<string, RevealedCredential>();
  for (const [graphIri, quads] of revealedQuads) {
    // get whole creds
    const vc = await store.get({
      graph: df.namedNode(graphIri),
    });
    // remove graph name
    const wholeDoc = vc.items.map((quad) =>
      df.quad(quad.subject, quad.predicate, quad.object)
    );

    // get associated proofs
    const proofs = await Promise.all(
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
    const metadata =
      (await getCredentialMetadata(graphIri, df, store, engine)) ?? [];

    // get anonymized credential by adding metadata to anonymized quads
    const anonymizedMetadata = metadata.map((quad) => {
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
      metadata === undefined ? quads : quads.concat(anonymizedMetadata);

    revealedCreds.set(graphIri, {
      wholeDoc,
      anonymizedDoc,
      proofs,
      anonToTerm: anonymizer.anonToTerm,
    });
  }

  return revealedCreds;
};

const generateVP = async (
  revealedCredsArray: Array<Map<string, RevealedCredential>>,
  df: DataFactory<RDF.Quad>
): Promise<VerifiablePresentation[] | { error: string }> => {
  const vps: VerifiablePresentation[] = [];
  for (const creds of revealedCredsArray) {
    // run BBS+
    const inputDocuments = Array.from(
      creds,
      ([_, { wholeDoc, anonymizedDoc, proofs, anonToTerm }]) => ({
        document: wholeDoc.filter((quad) => quad.predicate.value !== PROOF), // document without `proof` predicate
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
