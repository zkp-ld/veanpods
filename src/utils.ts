import type * as RDF from '@rdfjs/types';
import jsonld from 'jsonld';
import { type Quadstore } from 'quadstore';
import { type Engine } from 'quadstore-comunica';
import { type DataFactory } from 'rdf-data-factory';
import sparqljs from 'sparqljs';

// built-in JSON-LD contexts and sample VCs
import { customLoader } from './data/index.js';
import {
  type JsonBindingsType,
  type JsonResults,
  type ParsedQuery,
  type ParsedSparqlQuery,
  type ZkSubject,
  type ZkPredicate,
  type ZkObject,
  type ZkTriplePattern,
} from './types';
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

export const isZkSubject = (t: RDF.Term): t is ZkSubject =>
  t.termType === 'NamedNode' || t.termType === 'BlankNode';
export const isZkPredicate = (t: RDF.Term): t is ZkPredicate =>
  t.termType === 'NamedNode';
export const isZkObject = (t: RDF.Term): t is ZkObject =>
  t.termType === 'NamedNode' ||
  t.termType === 'BlankNode' ||
  t.termType === 'Literal';
export const isVariableTerm = (
  v: sparqljs.Variable
): v is sparqljs.VariableTerm => !('expression' in v);
export const isVariableTerms = (
  vs: sparqljs.Variable[]
): vs is sparqljs.VariableTerm[] => vs.every((v) => isVariableTerm(v));

/**
 * parse zk-SPARQL query
 *
 * @param query - zk-SPARQL query
 * @returns - parsed zk-SPARQL query, consisted of required variables, BGP triples, where clause, and prefixes
 */
export const parseQuery = (query: string): ParsedQuery | { error: string } => {
  const varsAndParsedQuery = parseSparqlQuery(query);
  if ('error' in varsAndParsedQuery) {
    return varsAndParsedQuery;
  }
  const { vars, parsedQuery } = varsAndParsedQuery;

  // extract Basic Graph Pattern (BGP) from parsed query
  const bgpAndNotBgps = getBGP(parsedQuery);
  if ('error' in bgpAndNotBgps) {
    return bgpAndNotBgps;
  }
  const { bgp, notBgps } = bgpAndNotBgps;

  const prefixes = parsedQuery.prefixes;

  return { vars, bgp, notBgps, prefixes };
};

// parse SPARQL query
const parseSparqlQuery = (
  query: string
): ParsedSparqlQuery | { error: string } => {
  const parser = new sparqljs.Parser();
  try {
    const parsedQuery = parser.parse(query);
    if (parsedQuery.type !== 'query') {
      return { error: 'query must be SELECT or ASK form' };
    }
    const queryType = parsedQuery.queryType;
    if (queryType === 'SELECT') {
      if (
        isWildcard(parsedQuery.variables) ||
        isVariableTerms(parsedQuery.variables)
      ) {
        return {
          vars: parsedQuery.variables,
          parsedQuery,
        };
      } else {
        return { error: 'query must not contain term expressions' };
      }
    } else if (queryType === 'ASK') {
      return {
        vars: [],
        parsedQuery,
      };
    } else {
      return { error: 'query must be SELECT or ASK form' };
    }
  } catch (error) {
    return { error: 'malformed query' };
  }
};

// extract a basic graph pattern (BGP) and not-basic graph patterns from parsed query
const getBGP = (
  parsedQuery: sparqljs.SelectQuery | sparqljs.AskQuery
):
  | { bgp: ZkTriplePattern[]; notBgps: sparqljs.Pattern[] }
  | { error: string } => {
  const where = parsedQuery.where;
  if (where === undefined) {
    return {
      error: 'WHERE clause must exist',
    };
  }

  // split BGPs and not BGPs
  const bgps = where.filter((p) => p.type === 'bgp');
  const notBgps = where.filter((p) => p.type !== 'bgp');

  // validate zk-SPARQL query
  if (bgps.length !== 1) {
    return {
      error: 'WHERE clause must consist of only one basic graph pattern',
    };
  }

  // extract triple patterns
  const bgp = (bgps[0] as sparqljs.BgpPattern).triples;
  if (!isTriplesWithoutPropertyPath(bgp)) {
    return { error: 'property paths are not supported' };
  }

  return { bgp, notBgps };
};

const isTripleWithoutPropertyPath = (
  triple: sparqljs.Triple
): triple is ZkTriplePattern =>
  !('type' in triple.predicate && triple.predicate.type === 'path');

const isTriplesWithoutPropertyPath = (
  triples: sparqljs.Triple[]
): triples is ZkTriplePattern[] =>
  triples.map(isTripleWithoutPropertyPath).every(Boolean);

export const getCredentialMetadata = async (
  graphIri: string,
  df: DataFactory,
  store: Quadstore,
  engine: Engine
): Promise<RDF.Quad[] | undefined> => {
  const query = `
  SELECT ?cred
  WHERE {
    GRAPH <${graphIri}> {
      ?cred a <${VC_TYPE}> .
    }
  }`;
  const bindingsStream = await engine.queryBindings(query); // TBD: try-catch
  const bindingsArray = await streamToArray(bindingsStream);
  const credIds = bindingsArray.map((bindings) => bindings.get('cred'));
  if (credIds.length === 0) {
    return undefined;
  }
  const credId = credIds[0];
  if (
    credId === undefined ||
    (credId.termType !== 'NamedNode' && credId.termType !== 'BlankNode')
  ) {
    return undefined;
  }
  const { items } = await store.get({ subject: credId });
  // remove graph name
  const cred = items.map((quad) =>
    df.quad(quad.subject, quad.predicate, quad.object, df.defaultGraph())
  );

  return cred;
};

export const getProofsId = async (
  graphIri: string,
  engine: Engine
): Promise<Array<RDF.Term | undefined>> => {
  const query = `
  SELECT ?proof
  WHERE {
    GRAPH <${graphIri}> {
      ?cred a <${VC_TYPE}> ;
        <${PROOF}> ?proof .
    }
  }`;
  const bindingsStream = await engine.queryBindings(query); // TBD: try-catch
  const bindingsArray = await streamToArray(bindingsStream);

  return bindingsArray.map((bindings) => bindings.get('proof'));
};

// utility function from [string, T][] to Map<string, T[]>
export const entriesToMap = <T>(
  entries: Array<[string, T]>
): Map<string, T[]> => {
  const res = new Map<string, T[]>();
  for (const entry of entries) {
    if (res.has(entry[0])) {
      res.get(entry[0])?.push(entry[1]);
    } else {
      res.set(entry[0], [entry[1]]);
    }
  }

  return res;
};

// ref: https://github.com/belayeng/quadstore-comunica/blob/master/spec/src/utils.ts
export const streamToArray = async <T>(
  source: RDF.ResultStream<T>
): Promise<T[]> => {
  return await new Promise((resolve, reject) => {
    const items: T[] = [];
    source.on('data', (item: T) => {
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

export const genJsonResults = (
  jsonVars: string[],
  bindingsArray: RDF.Bindings[]
): JsonResults => {
  const isNotNullOrUndefined = <T>(v?: T | null): v is T => v != null;

  const jsonBindingsArray = [];
  for (const bindings of bindingsArray) {
    const jsonBindingsEntries: Array<[string, JsonBindingsType]> = [...bindings]
      .map(([k, v]) => {
        let value: JsonBindingsType;
        if (v.termType === 'Literal') {
          if (v.language !== '') {
            value = {
              type: 'literal',
              value: v.value,
              'xml:lang': v.language,
            };
          } else if (
            v.datatype.value === 'http://www.w3.org/2001/XMLSchema#string'
          ) {
            value = {
              type: 'literal',
              value: v.value,
            };
          } else {
            value = {
              type: 'literal',
              value: v.value,
              datatype: v.datatype.value,
            };
          }
        } else if (v.termType === 'NamedNode') {
          value = {
            type: 'uri',
            value: v.value,
          };
        } else if (v.termType === 'BlankNode') {
          value = {
            type: 'bnode',
            value: v.value,
          };
        } else {
          return undefined;
        }

        return [k.value, value];
      })
      .filter(isNotNullOrUndefined) as Array<[string, JsonBindingsType]>;
    const jsonBindings = Object.fromEntries(jsonBindingsEntries);
    jsonBindingsArray.push(jsonBindings);
  }

  return {
    head: { vars: jsonVars },
    results: {
      bindings: jsonBindingsArray,
    },
  };
};

export const isWildcard = (
  vars: sparqljs.Variable[] | [sparqljs.Wildcard]
): vars is [sparqljs.Wildcard] =>
  vars.length === 1 && 'value' in vars[0] && vars[0].value === '*';

export const addBnodePrefix = (
  quad: RDF.Quad | RDF.Quad[]
): RDF.Quad | RDF.Quad[] => {
  const _addBnodePrefix = (quad: RDF.Quad): RDF.Quad => {
    if (
      quad.subject.termType === 'BlankNode' &&
      !quad.subject.value.startsWith(BNODE_PREFIX)
    ) {
      quad.subject.value = `${BNODE_PREFIX}${quad.subject.value}`;
    }
    if (
      quad.object.termType === 'BlankNode' &&
      !quad.object.value.startsWith(BNODE_PREFIX)
    ) {
      quad.object.value = `${BNODE_PREFIX}${quad.object.value}`;
    }
    if (
      quad.graph.termType === 'BlankNode' &&
      !quad.graph.value.startsWith(BNODE_PREFIX)
    ) {
      quad.graph.value = `${BNODE_PREFIX}${quad.graph.value}`;
    }

    return quad;
  };

  return Array.isArray(quad)
    ? quad.map((q) => _addBnodePrefix(q))
    : _addBnodePrefix(quad);
};

// ** functions for standard SPARQL endpoint (for debug) **

const respondToSelectQuery = async (
  query: string,
  parsedQuery: RDF.QueryBindings<RDF.AllMetadataSupport>
): Promise<{ jsonVars: string[]; bindingsArray: RDF.Bindings[] }> => {
  const bindingsStream = await parsedQuery.execute();
  const bindingsArray = await streamToArray(bindingsStream);
  const jsonVars =
    bindingsArray.length >= 1
      ? [...bindingsArray[0].keys()].map((k) => k.value)
      : [''];

  return { jsonVars, bindingsArray };
};

const respondToConstructQuery = async (
  parsedQuery: RDF.QueryQuads<RDF.AllMetadataSupport>
): Promise<jsonld.NodeObject> => {
  const quadsStream = await parsedQuery.execute();
  const quadsArray = await streamToArray(quadsStream);
  const quadsArrayWithBnodePrefix = addBnodePrefix(quadsArray);
  const quadsJsonld = await jsonld.fromRDF(quadsArrayWithBnodePrefix);
  const quadsJsonldCompact = await jsonld.compact(quadsJsonld, CONTEXTS, {
    documentLoader,
  });

  return quadsJsonldCompact;
};

export const processSparqlQuery = async (
  query: string,
  engine: Engine
): Promise<JsonResults | jsonld.NodeObject | string> => {
  // parse query
  let parsedQuery: RDF.Query<RDF.AllMetadataSupport>;
  try {
    parsedQuery = await engine.query(query, { unionDefaultGraph: true });
  } catch (error) {
    return 'malformed query';
  }

  // execute query
  if (parsedQuery.resultType === 'bindings') {
    const { jsonVars, bindingsArray } = await respondToSelectQuery(
      query,
      parsedQuery
    );

    return genJsonResults(jsonVars, bindingsArray);
  } else if (parsedQuery.resultType === 'quads') {
    return await respondToConstructQuery(parsedQuery);
  } else if (parsedQuery.resultType === 'boolean') {
    const askResult = await parsedQuery.execute();

    return { head: {}, boolean: askResult };
  } else {
    return 'invalid SPARQL query';
  }
};
