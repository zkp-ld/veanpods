import { DataFactory } from 'rdf-data-factory';
import { Engine } from 'quadstore-comunica';
import * as RDF from '@rdfjs/types';
import jsonld from 'jsonld';
import sparqljs from 'sparqljs';
import { Quadstore } from 'quadstore';
import { JsonBindingsType, JsonResults, ParsedQuery, VarsAndParsedQuery, VP, ZkSubject, ZkPredicate, ZkObject, ZkTripleBgp } from './types';

// built-in JSON-LD contexts and sample VCs
import { customLoader } from "./data/index.js";
const documentLoader = customLoader;

// ** constants ** //
const VC_TYPE = 'https://www.w3.org/2018/credentials#VerifiableCredential';
const PROOF = 'https://w3id.org/security#proof';
const BNODE_PREFIX = '_:';
const CONTEXTS = [
  'https://www.w3.org/2018/credentials/v1',
  'https://zkp-ld.org/bbs-termwise-2021.jsonld',
  'https://schema.org',
] as unknown as jsonld.ContextDefinition;

// ** functions ** //

export const isZkSubject =
  (t: RDF.Term): t is ZkSubject =>
  (t.termType === 'NamedNode'
    || t.termType === 'BlankNode');
export const isZkPredicate =
  (t: RDF.Term): t is ZkPredicate =>
    t.termType === 'NamedNode';
export const isZkObject =
  (t: RDF.Term): t is ZkObject =>
  (t.termType === 'NamedNode'
    || t.termType === 'BlankNode'
    || t.termType === 'Literal');
export const isVariableTerm =
  (v: sparqljs.Variable): v is sparqljs.VariableTerm =>
    !('expression' in v);
export const isVariableTerms =
  (vs: sparqljs.Variable[]): vs is sparqljs.VariableTerm[] =>
    vs.every((v) => isVariableTerm(v));

// parse zk-SPARQL query
export const parseQuery =
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
export const getBgpTriples =
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

export const getCredentialMetadata = async (
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

export const getProofsId = async (
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
export const entriesToMap = <T>(entries: [string, T][]) => {
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
export const streamToArray = <T>(source: RDF.ResultStream<T>): Promise<T[]> => {
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

export const genJsonResults =
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

export const isWildcard = (vars: sparqljs.Variable[] | [sparqljs.Wildcard]): vars is [sparqljs.Wildcard] =>
  vars.length === 1 && 'value' in vars[0] && vars[0].value === '*';

export const addBnodePrefix = (quad: RDF.Quad | RDF.Quad[]) => {
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