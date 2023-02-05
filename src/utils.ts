import { DataFactory } from 'rdf-data-factory';
import { Engine } from 'quadstore-comunica';
import * as RDF from '@rdfjs/types';
import jsonld from 'jsonld';
import sparqljs from 'sparqljs';
import { nanoid } from 'nanoid';
import { Quadstore } from 'quadstore';
import { BbsTermwiseSignatureProof2021, verifyProofMulti } from '@zkp-ld/rdf-signatures-bbs';

// built-in JSON-LD contexts and sample VCs
import { customLoader } from "./data/index.js";
const documentLoader = customLoader;

// ** constants ** //

const VC_TYPE = 'https://www.w3.org/2018/credentials#VerifiableCredential';
const PROOF = 'https://w3id.org/security#proof';
const GRAPH_VAR_PREFIX = 'ggggg';  // TBD
const ANONI_PREFIX = 'https://zkp-ld.org/.well-known/genid/anonymous/iri#';
const ANONB_PREFIX = 'https://zkp-ld.org/.well-known/genid/anonymous/bnid#';
const ANONL_PREFIX = 'https://zkp-ld.org/.well-known/genid/anonymous/literal#';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const NANOID_LEN = 6;
const BNODE_PREFIX = '_:';
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

// ** types ** //

type VP =
  {
    '@context': any;
    type: 'VerifiablePresentation';
    verifiableCredential: jsonld.NodeObject[];
  };
const VP_TEMPLATE: VP =
{
  '@context': CONTEXTS,
  type: 'VerifiablePresentation',
  verifiableCredential: [],
};

type ZkTermBgp = ZkSubjectBgp | ZkPredicateBgp | ZkObjectBgp;
type ZkSubjectBgp = sparqljs.IriTerm | sparqljs.VariableTerm;
type ZkPredicateBgp = sparqljs.IriTerm | sparqljs.VariableTerm;
type ZkObjectBgp = sparqljs.IriTerm | sparqljs.LiteralTerm | sparqljs.VariableTerm;
interface ZkTripleBgp {
  subject: ZkSubjectBgp,
  predicate: ZkPredicateBgp,
  object: ZkObjectBgp,
};

type ZkTerm = ZkSubject | ZkPredicate | ZkObject;
type ZkSubject = sparqljs.IriTerm | sparqljs.BlankTerm;
const isZkSubject =
  (t: RDF.Term): t is ZkSubject =>
  (t.termType === 'NamedNode'
    || t.termType === 'BlankNode');
type ZkPredicate = sparqljs.IriTerm;
const isZkPredicate =
  (t: RDF.Term): t is ZkPredicate =>
    t.termType === 'NamedNode';
type ZkObject = sparqljs.IriTerm | sparqljs.BlankTerm | sparqljs.LiteralTerm;
const isZkObject =
  (t: RDF.Term): t is ZkObject =>
  (t.termType === 'NamedNode'
    || t.termType === 'BlankNode'
    || t.termType === 'Literal');

type IdentifyCredsResultType = {
  extendedSolution: RDF.Bindings,
  graphIriToBgpTriple: Map<string, ZkTripleBgp[]>,
};

type ParsedQuery = sparqljs.SelectQuery | sparqljs.AskQuery;

type VarsAndParsedQuery = {
  requiredVars: sparqljs.VariableTerm[] | [sparqljs.Wildcard],
  parsedQuery: ParsedQuery,
}

export interface RevealedQuads {
  revealedQuads: RDF.Quad[];
  anonymizedQuads: RDF.Quad[];
};

export interface RevealedCreds {
  wholeDoc: RDF.Quad[];
  anonymizedDoc: RDF.Quad[];
  proofs: RDF.Quad[][];
};

interface FetchResult {
  extendedSolutions: RDF.Bindings[];
  revealedCredsArray: Map<string, RevealedCreds>[];
  requiredVars: sparqljs.VariableTerm[] | [sparqljs.Wildcard];
  anonToTerm: Map<string, ZkTerm>;
};

// ** functions ** //

export const processQuery = async (
  query: string,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine):
  Promise<JsonResults | { "error": string; }> => {
  // 1. parse zk-SPARQL query and execute SELECT on internal quadstore
  const queryResult = await fetch(query, store, df, engine);
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
    const derivedProofs: any = await suite.deriveProofMultiRDF({
      inputDocuments,
      documentLoader,
    });

    // serialize derived VCs as JSON-LD documents
    const derivedVcs: any[] = [];
    for (const { document, proof: proofs } of derivedProofs) {
      // connect document and proofs
      const documentId = document.find(
        (quad: RDF.Quad) => quad.predicate.value === RDF_TYPE && quad.object.value === VC_TYPE)
        .subject;
      const proofGraphs = [];
      for (const proof of proofs) {
        const proofGraphId = df.blankNode();
        const proofGraph = proof.map((quad: RDF.Quad) =>
          df.quad(quad.subject, quad.predicate, quad.object, proofGraphId));
        proofGraphs.push(proofGraph);
        document.push(df.quad(documentId, df.namedNode(PROOF), proofGraphId));
      }
      const cred = document.concat(proofGraphs.flat());
      // add bnode prefix `_:` to blank node ids
      const credWithBnodePrefix = addBnodePrefix(cred);
      const credJson = await jsonld.fromRDF(credWithBnodePrefix);
      // to compact JSON-LD
      const credJsonCompact = await jsonld.compact(credJson, CONTEXTS, { documentLoader });
      // shape it to be a VC
      const derivedVc: any = await jsonld.frame(
        credJsonCompact,
        VC_FRAME,
        { documentLoader }
      );
      derivedVcs.push(derivedVc);
    }

    // serialize VP
    const vp = { ...VP_TEMPLATE };
    vp['verifiableCredential'] = derivedVcs;
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

const isVariableTerm =
  (v: sparqljs.Variable): v is sparqljs.VariableTerm =>
    !('expression' in v);
const isVariableTerms =
  (vs: sparqljs.Variable[]): vs is sparqljs.VariableTerm[] =>
    vs.every((v) => isVariableTerm(v));

// parse zk-SPARQL query
const parseQuery =
  (query: string): VarsAndParsedQuery | { error: string } => {
    const parser = new sparqljs.Parser();
    try {
      const parsedQuery = parser.parse(query);
      if (parsedQuery.type !== 'query') {
        return { error: 'query must be SELECT or ASK form' };
      }
      const queryType = parsedQuery.queryType;
      if (queryType === 'SELECT') {
        if (isWildcard(parsedQuery.variables)
          || (isVariableTerms(parsedQuery.variables))) {
          return {
            requiredVars: parsedQuery.variables,
            parsedQuery,
          };
        } else {
          return { error: 'query must not contain term expressions' }
        }
      } else if (queryType === 'ASK') {
        return {
          requiredVars: [],
          parsedQuery,
        };
      } else {
        return { error: 'query must be SELECT or ASK form' };
      }
    } catch (error) {
      return { error: 'malformed query' };
    }
  }

// extract Basic Graph Pattern (BGP) triples from parsed query
const getBgpTriples =
  (parsedQuery: ParsedQuery): ZkTripleBgp[] | { error: string } => {
    // validate zk-SPARQL query
    const bgpPatterns = parsedQuery.where?.filter((p) => p.type === 'bgp');
    if (bgpPatterns?.length !== 1) {
      return { error: 'WHERE clause must consist of only one basic graph pattern' }
    }

    // extract BGP triples
    const bgpPattern = bgpPatterns[0] as sparqljs.BgpPattern;
    const bgpTriples = bgpPattern.triples;
    if (!isTriplesWithoutPropertyPath(bgpTriples)) {
      return { error: 'property paths are not supported' };
    };

    return bgpTriples;
  }

const isTripleWithoutPropertyPath =
  (triple: sparqljs.Triple):
    triple is ZkTripleBgp =>
    'type' in triple.predicate && triple.predicate.type === 'path' ? false : true;

const isTriplesWithoutPropertyPath =
  (triples: sparqljs.Triple[]):
    triples is ZkTripleBgp[] =>
    triples.map(isTripleWithoutPropertyPath).every(Boolean);

// get extended SPARQL solutions, which are SPARQL solutions with _names of graphs_
// where each input BGP triples is included
const getExtendedSolutions = async (
  bgpTriples: sparqljs.Triple[],
  parsedQuery: ParsedQuery,
  df: DataFactory<RDF.Quad>,
  engine: Engine
) => {
  // construct an extended SPARQL query
  const extendedGraphPatterns: sparqljs.GraphPattern[]
    = bgpTriples.map((triple, i) => (
      {
        type: 'graph',
        patterns: [{
          type: 'bgp',
          triples: [triple]
        }],
        name: df.variable(`${GRAPH_VAR_PREFIX}${i}`),
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

const fetch = async (
  query: string,
  store: Quadstore,
  df: DataFactory<RDF.Quad>,
  engine: Engine,
): Promise<FetchResult | { error: string }> => {
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

  const gVarToBgpTriple: Record<string, ZkTripleBgp>
    = Object.assign({}, ...bgpTriples.map((triple, i) => ({
      [`${GRAPH_VAR_PREFIX}${i}`]: triple
    })));

  // get extended bindings, i.e.,
  // bindings (SELECT query responses) + associated graph names corresponding to each BGP triples
  const extendedSolutions = await getExtendedSolutions(
    bgpTriples, parsedQuery, df, engine);

  // get revealed and anonymized credentials
  const anonymizer = new Anonymizer(df);
  const revealedCredsArray = await Promise.all(
    extendedSolutions
      .map((extendedSolution) =>
        identifyCreds(
          extendedSolution,
          gVarToBgpTriple))
      .map(({ extendedSolution, graphIriToBgpTriple }) =>
        getRevealedQuads(
          graphIriToBgpTriple,
          extendedSolution,
          requiredVars,
          df,
          anonymizer))
      .map(async (revealedQuads) =>
        getRevealedCreds(
          await revealedQuads,
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

// get `graphIriToBgpTriple`
// e.g., { ggggg0: [ (:s1 :p1 :o1), (:s1 :p2 :o2) ], ggggg1: [ (:s1 :p3 :o3 )] }
const identifyCreds = (
  extendedSolution: RDF.Bindings,
  gVarToBgpTriple: Record<string, ZkTripleBgp>,
): IdentifyCredsResultType => {
  const graphIriAndGraphVars = [...extendedSolution]
    .filter((b) => b[0].value.startsWith(GRAPH_VAR_PREFIX))
    .map(([gVar, gIri]) => [gIri.value, gVar.value]);
  const graphIriAndBgpTriples: [string, ZkTripleBgp][] = graphIriAndGraphVars
    .map(([gIri, gVar]) => [gIri, gVarToBgpTriple[gVar]]);
  const graphIriToBgpTriple = entriesToMap(graphIriAndBgpTriples);
  return ({ extendedSolution, graphIriToBgpTriple });
};

// get `revealedQuads`
const getRevealedQuads = async (
  graphIriToBgpTriple: Map<string, ZkTripleBgp[]>,
  bindings: RDF.Bindings,
  vars: sparqljs.VariableTerm[] | [sparqljs.Wildcard],
  df: DataFactory<RDF.Quad>,
  anonymizer: Anonymizer,
) => {
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
      if (subject != undefined && isZkSubject(subject)
        && predicate != undefined && isZkPredicate(predicate)
        && object != undefined && isZkObject(object)) {
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
) => {
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
          if (proofId == undefined) {
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
        subject != undefined ? subject : quad.subject,
        predicate != undefined ? predicate : quad.predicate,
        object != undefined ? object : quad.object,
        df.defaultGraph(),
      );
    });
    const anonymizedDoc =
      metadata == undefined ? quads : quads.concat(anonymizedMetadata);

    revealedCreds.set(graphIri, {
      wholeDoc,
      anonymizedDoc,
      proofs,
    });
  }
  return revealedCreds;
}

class Anonymizer {
  iriToAnonMap: Map<string, sparqljs.IriTerm>;
  bnodeToAnonMap: Map<string, sparqljs.IriTerm>;
  literalToAnonMap: Map<string, sparqljs.LiteralTerm>;
  anonToTerm: Map<string, ZkTerm>;
  df: DataFactory<RDF.Quad>;

  constructor(df: DataFactory<RDF.Quad>) {
    this.iriToAnonMap = new Map<string, sparqljs.IriTerm>();
    this.bnodeToAnonMap = new Map<string, sparqljs.IriTerm>();
    this.literalToAnonMap = new Map<string, sparqljs.LiteralTerm>();
    this.anonToTerm = new Map<string, ZkTerm>();
    this.df = df;
  }

  private _genKey = (val: ZkTerm) =>
    val.termType === 'Literal' ?
      `${val.value}:${nanoid(NANOID_LEN)}` :
      `${val.value}`;

  anonymize = (val: ZkSubject | ZkPredicate) => {
    const key = this._genKey(val);
    let anon: sparqljs.IriTerm;
    if (val.termType === 'NamedNode') {
      const result = this.iriToAnonMap.get(key);
      if (result != undefined) {
        return result;
      }
      const anonIri = `${ANONI_PREFIX}${nanoid(NANOID_LEN)}`;
      anon = this.df.namedNode(anonIri) as sparqljs.IriTerm;
      this.iriToAnonMap.set(key, anon);
      this.anonToTerm.set(anonIri, val);
    } else {
      const result = this.bnodeToAnonMap.get(key);
      if (result != undefined) {
        return result;
      }
      const anonBnid = `${ANONB_PREFIX}${nanoid(NANOID_LEN)}`;
      anon = this.df.namedNode(anonBnid) as sparqljs.IriTerm;
      this.bnodeToAnonMap.set(key, anon);
      this.anonToTerm.set(anonBnid, val);
    }
    return anon;
  };

  get = (val: ZkSubject | ZkPredicate) => {
    const key = this._genKey(val);
    if (val.termType === 'NamedNode') {
      return this.iriToAnonMap.get(key);
    } else {
      return this.bnodeToAnonMap.get(key);
    }
  };

  anonymizeObject = (val: ZkObject) => {
    if (val.termType === 'NamedNode' || val.termType === 'BlankNode') {
      return this.anonymize(val);
    }
    const key = this._genKey(val);
    const result = this.literalToAnonMap.get(key);
    if (result != undefined) {
      return result;
    }
    const anonLiteral = `${ANONL_PREFIX}${nanoid(NANOID_LEN)}`;
    const languageOrDatatype = val.language !== '' ? val.language : val.datatype;
    const anon = this.df.literal(anonLiteral, languageOrDatatype) as sparqljs.LiteralTerm;
    this.literalToAnonMap.set(key, anon);
    this.anonToTerm.set(anonLiteral, val);
    return anon;
  };

  getObject = (val: ZkObject) => {
    const key = this._genKey(val);
    if (val.termType === 'NamedNode' || val.termType === 'BlankNode') {
      return this.get(val);
    } else {
      return this.literalToAnonMap.get(key);
    }
  };
}

const anonymizeQuad = (
  bgpTriples: ZkTripleBgp[],
  vars: sparqljs.VariableTerm[],
  bindings: RDF.Bindings,
  df: DataFactory<RDF.Quad>,
  anonymizer: Anonymizer,
) => bgpTriples.flatMap(
  (triple) => {
    let subject: RDF.Term | undefined;
    if (triple.subject.termType !== 'Variable') {
      subject = triple.subject;
    } else if (vars.some((v) => v.value === triple.subject.value)) {
      subject = bindings.get(triple.subject);
    } else {
      const val = bindings.get(triple.subject);
      if (val != undefined && isZkSubject(val)) {
        subject = anonymizer.anonymize(val);
      }
    }

    let predicate: RDF.Term | undefined;
    if (triple.predicate.termType !== 'Variable') {
      predicate = triple.predicate;
    } else if (vars.some((v) => v.value === triple.predicate.value)) {
      predicate = bindings.get(triple.predicate);
    } else {
      const val = bindings.get(triple.predicate);
      if (val != undefined && isZkPredicate(val)) {
        predicate = anonymizer.anonymize(val);
      }
    }

    let object: RDF.Term | undefined;
    if (triple.object.termType !== 'Variable') {
      object = triple.object;
    } else if (vars.some((v) => v.value === triple.object.value)) {
      object = bindings.get(triple.object);
    } else {
      const val = bindings.get(triple.object);
      if (val != undefined && isZkObject(val)) {
        object = anonymizer.anonymizeObject(val);
      }
    }

    const graph = df.defaultGraph();

    if (subject != undefined && isZkSubject(subject)
      && predicate != undefined && isZkPredicate(predicate)
      && object != undefined && isZkObject(object)) {
      return [df.quad(subject, predicate, object, graph)];
    } else {
      return []
    }
  }
);

const getCredentialMetadata = async (
  graphIri: string,
  df: DataFactory,
  store: Quadstore,
  engine: Engine,
) => {
  const query = `
  SELECT ?cred
  WHERE {
    GRAPH <${graphIri}> {
      ?cred a <${VC_TYPE}> .
    }
  }`;
  const bindingsStream = await engine.queryBindings(query);  // TBD: try-catch
  const bindingsArray = await streamToArray(bindingsStream);
  const credIds = bindingsArray.map((bindings) => bindings.get('cred'));
  if (credIds.length === 0) {
    return undefined;
  }
  const credId = credIds[0];
  if (credId == undefined
    || (credId.termType !== 'NamedNode'
      && credId.termType !== 'BlankNode')) {
    return undefined;
  }
  const { items } = await store.get({ subject: credId });
  // remove graph name
  const cred = items.map(
    (quad) => df.quad(
      quad.subject,
      quad.predicate,
      quad.object,
      df.defaultGraph()));
  return cred;
};

const getProofsId = async (
  graphIri: string,
  engine: Engine
) => {
  const query = `
  SELECT ?proof
  WHERE {
    GRAPH <${graphIri}> {
      ?cred a <${VC_TYPE}> ;
        <${PROOF}> ?proof .
    }
  }`;
  const bindingsStream = await engine.queryBindings(query);  // TBD: try-catch
  const bindingsArray = await streamToArray(bindingsStream);
  return bindingsArray.map((bindings) => bindings.get('proof'));
};

const deduplicateQuads = (quads: RDF.Quad[]) =>
  quads.filter((quad1, index, self) =>
    index === self.findIndex((quad2) => (quad1.equals(quad2))));

// utility function from [string, T][] to Map<string, T[]>
const entriesToMap = <T>(entries: [string, T][]) => {
  const res = new Map<string, T[]>();
  for (const entry of entries) {
    if (res.has(entry[0])) {
      res.get(entry[0])?.push(entry[1]);
    } else {
      res.set(entry[0], [entry[1]]);
    };
  };
  return res;
};

// ref: https://github.com/belayeng/quadstore-comunica/blob/master/spec/src/utils.ts
const streamToArray = <T>(source: RDF.ResultStream<T>): Promise<T[]> => {
  return new Promise((resolve, reject) => {
    const items: T[] = [];
    source.on('data', (item) => {
      items.push(item);
    });
    source.on('end', () => {
      resolve(items);
    });
    source.on('error', (err) => {
      reject(err);
    });
  });
};

type JsonBindingsUriType = {
  type: 'uri', value: string
};
type JsonBindingsLiteralType = {
  type: 'literal', value: string, 'xml:lang'?: string, datatype?: string
};
type JsonBindingsBnodeType = {
  type: 'bnode', value: string
};
type JsonBindingsType = JsonBindingsUriType | JsonBindingsLiteralType | JsonBindingsBnodeType;
type JsonResults = {
  head: {
    vars: string[],
  },
  results: {
    bindings: {
      [k: string]: JsonBindingsType,
    }[]
  }
};

const genJsonResults =
  (jsonVars: string[], bindingsArray: RDF.Bindings[]): JsonResults => {
    const isNotNullOrUndefined = <T>(v?: T | null): v is T => null != v;

    const jsonBindingsArray = [];
    for (const bindings of bindingsArray) {
      const jsonBindingsEntries: [string, JsonBindingsType][] = [...bindings].map(([k, v]) => {
        let value: JsonBindingsType;
        if (v.termType === 'Literal') {
          if (v.language !== '') {
            value = {
              type: 'literal',
              value: v.value,
              'xml:lang': v.language
            };
          } else if (v.datatype.value === 'http://www.w3.org/2001/XMLSchema#string') {
            value = {
              type: 'literal',
              value: v.value
            };
          } else {
            value = {
              type: 'literal',
              value: v.value,
              datatype: v.datatype.value
            };
          }
        } else if (v.termType === 'NamedNode') {
          value = {
            type: 'uri',
            value: v.value
          };
        } else if (v.termType === 'BlankNode') {
          value = {
            type: 'bnode',
            value: v.value
          };
        } else {
          return undefined;
        };
        return [k.value, value];
      }).filter(isNotNullOrUndefined) as [string, JsonBindingsType][];
      const jsonBindings = Object.fromEntries(jsonBindingsEntries);
      jsonBindingsArray.push(jsonBindings);
    }
    return {
      "head": { "vars": jsonVars },
      "results": {
        "bindings": jsonBindingsArray
      }
    };
  }

const isWildcard = (vars: sparqljs.Variable[] | [sparqljs.Wildcard]): vars is [sparqljs.Wildcard] =>
  vars.length === 1 && 'value' in vars[0] && vars[0].value === '*';

const addBnodePrefix = (quad: RDF.Quad | RDF.Quad[]) => {
  const _addBnodePrefix = (quad: RDF.Quad) => {
    if (quad.subject.termType === 'BlankNode'
      && !quad.subject.value.startsWith(BNODE_PREFIX)) {
      quad.subject.value = `${BNODE_PREFIX}${quad.subject.value}`;
    }
    if (quad.object.termType === 'BlankNode'
      && !quad.object.value.startsWith(BNODE_PREFIX)) {
      quad.object.value = `${BNODE_PREFIX}${quad.object.value}`;
    }
    if (quad.graph.termType === 'BlankNode'
      && !quad.graph.value.startsWith(BNODE_PREFIX)) {
      quad.graph.value = `${BNODE_PREFIX}${quad.graph.value}`;
    }
    return quad;
  }

  return Array.isArray(quad) ? quad.map((q) => _addBnodePrefix(q)) : _addBnodePrefix(quad);
}

// ** functions for standard SPARQL endpoint (for debug) **

const respondToSelectQuery = async (query: string, parsedQuery: RDF.QueryBindings<RDF.AllMetadataSupport>) => {
  const bindingsStream = await parsedQuery.execute();
  const bindingsArray = await streamToArray(bindingsStream);

  // // extract variables from SELECT query
  // const varsAndParsedQuery = parseQuery(query);
  // if ('error' in varsAndParsedQuery) {
  //   throw new Error(varsAndParsedQuery.error);
  // }
  // const vars = varsAndParsedQuery.vars;

  // // send response
  // let jsonVars: string[];
  // if (vars.length === 1 && 'value' in vars[0] && vars[0].value === '*') {
  //   // SELECT * WHERE {...}
  //   jsonVars = bindingsArray.length >= 1 ? [...bindingsArray[0].keys()].map((k) => k.value) : [''];
  // } else {
  //   // SELECT ?s ?p ?o WHERE {...}
  //   jsonVars = vars.map((v) => v.value);
  // }

  let jsonVars = bindingsArray.length >= 1 ? [...bindingsArray[0].keys()].map((k) => k.value) : [''];
  return { jsonVars, bindingsArray };
};

const respondToConstructQuery = async (parsedQuery: RDF.QueryQuads<RDF.AllMetadataSupport>) => {
  const quadsStream = await parsedQuery.execute();
  const quadsArray = await streamToArray(quadsStream);
  const quadsArrayWithBnodePrefix = addBnodePrefix(quadsArray);
  const quadsJsonld = await jsonld.fromRDF(quadsArrayWithBnodePrefix);
  const quadsJsonldCompact = await jsonld.compact(quadsJsonld, CONTEXTS, { documentLoader });
  return quadsJsonldCompact;
};

export const processSparqlQuery = async (
  query: string,
  engine: Engine):
  Promise<JsonResults | jsonld.NodeObject | string> => {
  // parse query
  let parsedQuery: RDF.Query<RDF.AllMetadataSupport>;
  try {
    parsedQuery = await engine.query(query, { unionDefaultGraph: true });
  } catch (error) {
    return "malformed query";
  }

  // execute query
  if (parsedQuery.resultType === 'bindings') {
    const { jsonVars, bindingsArray } = await respondToSelectQuery(query, parsedQuery)
    return genJsonResults(jsonVars, bindingsArray);
  } else if (parsedQuery.resultType === 'quads') {
    return await respondToConstructQuery(parsedQuery);
  } else if (parsedQuery.resultType === 'boolean') {
    const askResult = await parsedQuery.execute();
    return { head: {}, boolean: askResult };
  } else {
    return "invalid SPARQL query";
  }
}