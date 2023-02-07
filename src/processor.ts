import type * as RDF from '@rdfjs/types';
import { BbsTermwiseSignatureProof2021 } from '@zkp-ld/rdf-signatures-bbs';
import jsonld from 'jsonld';
import { customAlphabet } from 'nanoid';
import { type Quadstore } from 'quadstore';
import { type Engine } from 'quadstore-comunica';
import { type DataFactory } from 'rdf-data-factory';
import sparqljs from 'sparqljs';
import { anonymizeQuad, Anonymizer } from './anonymizer.js';
import { customLoader } from "./data/index.js";
import { type InternalQueryResult, type IdentifyCredsResultType, type JsonResults, type ParsedQuery, type RevealedCreds, type VP, type ZkTripleBgp } from './types';
import { addBnodePrefix, entriesToMap, genJsonResults, getBgpTriples, getCredentialMetadata, getProofsId, isWildcard, isZkObject, isZkPredicate, isZkSubject, parseQuery, streamToArray } from './utils.js';

// built-in JSON-LD contexts and sample VCs
const documentLoader = customLoader;

// ** constants ** //
const GRAPH_VAR_LENGTH = 20;
const graphVarGenerator = customAlphabet('abcdefghijklmnopqrstuvwxyz', GRAPH_VAR_LENGTH);
const PROOF = 'https://w3id.org/security#proof';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const VC_TYPE = 'https://www.w3.org/2018/credentials#VerifiableCredential';
const CONTEXTS = [
  'https://www.w3.org/2018/credentials/v1',
  'https://zkp-ld.org/bbs-termwise-2021.jsonld',
  'https://schema.org',
] as unknown as jsonld.ContextDefinition;
const VC_FRAME =
{
  '@context': CONTEXTS,
  type: 'VerifiableCredential',
  proof: {}  // explicitly required otherwise `sec:proof` is used instead
};
const VP_TEMPLATE: VP =
{
  '@context': CONTEXTS,
  type: 'VerifiablePresentation',
  verifiableCredential: [],
};

export const processQuery = async (
  query: string,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine):
  Promise<JsonResults | { "error": string; }> => {
  // 1. parse zk-SPARQL query and execute SELECT on internal quadstore
  const queryResult = await executeInternalQueries(query, store, df, engine);
  if ('error' in queryResult) {
    return queryResult;
  }
  const {
    extendedSolutions,
    revealedCredsArray,
    requiredVars,
    anonToTerm
  } = queryResult;

  // 2. generate VPs
  const vps: VP[] = [];
  for (const creds of revealedCredsArray) {
    // run BBS+
    const inputDocuments = Array.from(creds,
      ([_, { wholeDoc, anonymizedDoc, proofs }]) => ({
        document: wholeDoc.filter((quad) => quad.predicate.value !== PROOF),  // document without `proof` predicate
        proofs,
        revealedDocument: anonymizedDoc.filter((quad) => quad.predicate.value !== PROOF),  // document without `proof` predicate
        anonToTerm
      }));
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
        (quad) => quad.predicate.value === RDF_TYPE && quad.object.value === VC_TYPE);
      if (vc === undefined) {
        return { "error": "a stored VC does not have Identifier" };
      }
      const credentialId = vc.subject;
      const proofGraphs: RDF.Quad[][] = [];
      for (const proof of proofs) {
        const proofGraphId = df.blankNode();
        const proofGraph = proof.map((quad) =>
          df.quad(quad.subject, quad.predicate, quad.object, proofGraphId));
        proofGraphs.push(proofGraph);
        document.push(df.quad(credentialId, df.namedNode(PROOF), proofGraphId));
      }
      const cred = document.concat(proofGraphs.flat());
      // add bnode prefix `_:` to blank node ids
      const credWithBnodePrefix = addBnodePrefix(cred);
      const credJson = await jsonld.fromRDF(credWithBnodePrefix);
      // to compact JSON-LD
      const credJsonCompact = await jsonld.compact(credJson, CONTEXTS, { documentLoader });
      // shape it to be a VC
      const derivedVc = await jsonld.frame(
        credJsonCompact,
        VC_FRAME,
        { documentLoader }
      );
      derivedVcs.push(derivedVc);
    }

    // serialize VP
    const vp = { ...VP_TEMPLATE };
    vp.verifiableCredential = derivedVcs;
    vps.push(vp);

    // // debug: verify derived VC
    // // separate document and proofs
    // const verified = await verifyProofMulti(derivedVcs,
    //   {
    //     suite,
    //     documentLoader,
    //     purpose: new jsigs.purposes.AssertionProofPurpose()
    //   });
    // console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
  }

  // 3. remove unrevealed bindings from extended solutions
  const requiredVarNames = requiredVars.map((v) => v.value);
  const revealedSolutions = isWildcard(requiredVars) ?
    extendedSolutions :
    extendedSolutions.map(
      (extendedSolution) => extendedSolution.filter(
        (_, key) => requiredVarNames.includes(key.value))
    );

  // 4. add VPs (or VCs) to each corresponding solutions
  const revealedSolutionWithVPs = revealedSolutions.map(
    (revealedSolution, i) =>
      revealedSolution.set('vp', df.literal(
        `${JSON.stringify(vps[i], null, 2)}`)));

  // 5. send response
  let jsonVars: string[];
  if (isWildcard(requiredVars)) {
    // SELECT * WHERE {...}
    jsonVars = extendedSolutions.length >= 1 ?
      [...extendedSolutions[0].keys()].map((k) => k.value) :
      [''];
  } else {
    // SELECT ?s ?p ?o WHERE {...}
    jsonVars = requiredVars.map((v) => v.value);
  }
  jsonVars.push('vp');

  return genJsonResults(jsonVars, revealedSolutionWithVPs);
};

const executeInternalQueries = async (
  query: string,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine,
): Promise<InternalQueryResult | { error: string }> => {
  // parse zk-SPARQL query
  const varsAndParsedQuery = parseQuery(query);
  if ('error' in varsAndParsedQuery) {
    return varsAndParsedQuery;
  }
  const { requiredVars, parsedQuery } = varsAndParsedQuery;

  // extract Basic Graph Pattern (BGP) triples from parsed query
  const bgpTriples = getBgpTriples(parsedQuery);
  if ('error' in bgpTriples) {
    return bgpTriples; // TBD
  }

  // generate random prefix for temporary variables of internal queries
  const graphVarPrefix = graphVarGenerator();

  // pairs a temporary variable and its corresponding BGP triple
  const graphVarAndBgpTriple: Array<[string, ZkTripleBgp]> =
    bgpTriples.map((triple, i) => [`${graphVarPrefix}${i}`, triple]);

  // get extended bindings, i.e.,
  // bindings (SELECT query responses) + associated graph names corresponding to each BGP triples
  const extendedSolutions = await getExtendedSolutions(
    bgpTriples, parsedQuery, graphVarPrefix, df, engine);

  // get revealed and anonymized credentials
  const anonymizer = new Anonymizer(df);
  const revealedCredsArray = await Promise.all(
    extendedSolutions
      .map((extendedSolution) =>
        identifyCreds(
          extendedSolution,
          graphVarAndBgpTriple))
      .map(({ extendedSolution, graphIriToBgpTriple }) =>
        getRevealedQuads(
          graphIriToBgpTriple,
          extendedSolution,
          requiredVars,
          df,
          anonymizer))
      .map(async (revealedQuads) =>
        await getRevealedCreds(
          revealedQuads,
          store,
          df,
          engine,
          anonymizer)));

  const anonToTerm = anonymizer.anonToTerm;

  return {
    extendedSolutions,
    revealedCredsArray,
    requiredVars,
    anonToTerm
  };
}

// get `graphIriToBgpTriple` from extended solution and gVarToBgpTriple
//
// example parameters:
//   extendedSolution (partially) = 
//     { "ggggg0": "http://example.org/graph0",
//       "ggggg1": "http://example.org/graph1",
//       "ggggg2": "http://example.org/graph0" }
//   gVarToBgpTriple =
//     { "ggggg0": (:s0 :p0 :o0),
//       "ggggg1": (:s1 :p1 :o1),
//       "ggggg2": (:s2 :p2 :o2) }
const identifyCreds = (
  extendedSolution: RDF.Bindings,
  gVarAndBgpTriple: Array<[string, ZkTripleBgp]>,
): IdentifyCredsResultType => {
  // graphIriAndBgpTriples =
  //   [ [ "http://example.org/graph0", (:s0 :p0 :o0) ],
  //     [ "http://example.org/graph1", (:s1 :p1 :o1) ],
  //     [ "http://example.org/graph0", (:s2 :p2 :o2) ] ]
  const graphIriAndBgpTriples: Array<[string, ZkTripleBgp]> = [];
  for (const [gVar, bgpTriple] of gVarAndBgpTriple) {
    const uri = extendedSolution.get(gVar);
    if (uri === undefined || uri.termType !== "NamedNode") continue;
    graphIriAndBgpTriples.push([uri.value, bgpTriple]);
  };

  // graphIriToBgpTriple =
  //   { "http://example.org/graph0": [ (:s0 :p0 :o0), (:s2 :p2 :o2) ],
  //     "http://example.org/graph1": [ (:s1 :p1 :o1 ) ] }
  const graphIriToBgpTriple = entriesToMap(graphIriAndBgpTriples);

  return ({ extendedSolution, graphIriToBgpTriple });
};

// get `revealedQuads`
const getRevealedQuads = (
  graphIriToBgpTriple: Map<string, ZkTripleBgp[]>,
  bindings: RDF.Bindings,
  vars: sparqljs.VariableTerm[] | [sparqljs.Wildcard],
  df: DataFactory<RDF.Quad>,
  anonymizer: Anonymizer,
): Map<string, RDF.Quad[]> => {
  const result = new Map<string, RDF.Quad[]>();
  for (const [credGraphIri, bgpTriples] of graphIriToBgpTriple.entries()) {
    const revealedQuads = bgpTriples.flatMap((triple) => {
      const subject = triple.subject.termType === 'Variable'
        ? bindings.get(triple.subject) : triple.subject;
      const predicate = triple.predicate.termType === 'Variable'
        ? bindings.get(triple.predicate) : triple.predicate;
      const object = triple.object.termType === 'Variable'
        ? bindings.get(triple.object) : triple.object;
      const graph = df.defaultGraph()
      if (subject !== undefined && isZkSubject(subject)
        && predicate !== undefined && isZkPredicate(predicate)
        && object !== undefined && isZkObject(object)) {
        return [df.quad(subject, predicate, object, graph)];
      } else {
        return [];
      }
    });
    const anonymizedQuads = isWildcard(vars)
      ? revealedQuads.map((quad) => df.fromQuad(quad)) // deep copy
      : anonymizeQuad(bgpTriples, vars, bindings, df, anonymizer);
    result.set(credGraphIri, anonymizedQuads);
  }

  return result;
};

// get `revealedCreds`
const getRevealedCreds = async (
  revealedQuads: Map<string, RDF.Quad[]>,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine,
  anonymizer: Anonymizer,
): Promise<Map<string, RevealedCreds>> => {
  const revealedCreds = new Map<string, RevealedCreds>();
  for (const [graphIri, quads] of revealedQuads) {
    // get whole creds
    const vc = await store.get({
      graph: df.namedNode(graphIri)
    });
    // remove graph name
    const wholeDoc = vc.items
      .map((quad) => df.quad(quad.subject, quad.predicate, quad.object));

    // get associated proofs
    const proofs = await Promise.all(
      (await getProofsId(graphIri, engine)).flatMap(
        async (proofId) => {
          if (proofId === undefined) {
            return [];
          }
          const proof = await store.get({
            graph: df.namedNode(proofId.value)
          });

          return proof.items;
        }));

    // get credential metadata
    const metadata = await getCredentialMetadata(graphIri, df, store, engine)
      ?? [];

    // get anonymized credential by adding metadata to anonymized quads
    const anonymizedMetadata = metadata.map((quad) => {
      const subject = isZkSubject(quad.subject) ?
        anonymizer.get(quad.subject) : quad.subject;
      const predicate = isZkPredicate(quad.predicate) ?
        anonymizer.get(quad.predicate) : quad.predicate;
      const object = isZkObject(quad.object) ?
        anonymizer.getObject(quad.object) : quad.object;

      return df.quad(
        subject !== undefined ? subject : quad.subject,
        predicate !== undefined ? predicate : quad.predicate,
        object !== undefined ? object : quad.object,
        df.defaultGraph(),
      );
    });
    const anonymizedDoc =
      metadata === undefined ? quads : quads.concat(anonymizedMetadata);

    revealedCreds.set(graphIri, {
      wholeDoc,
      anonymizedDoc,
      proofs,
    });
  }

  return revealedCreds;
}

// get extended SPARQL solutions, which are SPARQL solutions with _names of graphs_
// where each input BGP triples is included
const getExtendedSolutions = async (
  bgpTriples: sparqljs.Triple[],
  parsedQuery: ParsedQuery,
  graphVarPrefix: string,
  df: DataFactory<RDF.Quad>,
  engine: Engine
): Promise<RDF.Bindings[]> => {
  // construct an extended SPARQL query
  const extendedGraphPatterns: sparqljs.GraphPattern[]
    = bgpTriples.map((triple, i) => (
      {
        type: 'graph',
        patterns: [{
          type: 'bgp',
          triples: [triple]
        }],
        name: df.variable(`${graphVarPrefix}${i}`),
      }
    ));
  const where = parsedQuery
    .where?.filter((p) => p.type !== 'bgp')  // remove original BGPs
    .concat(extendedGraphPatterns);  // add extended BGPs
  const extendedQuery: sparqljs.SelectQuery = {
    type: 'query',
    queryType: 'SELECT',
    distinct: true,
    variables: [new sparqljs.Wildcard()],
    prefixes: parsedQuery.prefixes,
    where,
  };

  // execute extended query and get extended solutions
  const generator = new sparqljs.Generator();
  const generatedQuery = generator.stringify(extendedQuery);
  const bindingsStream = await engine.queryBindings(generatedQuery, { unionDefaultGraph: true });
  const extendedSolutions = await streamToArray(bindingsStream);

  return extendedSolutions;
};
