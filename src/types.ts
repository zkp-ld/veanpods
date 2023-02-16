import type * as RDF from '@rdfjs/types';
import type jsonld from 'jsonld';
import type sparqljs from 'sparqljs';

export interface VerifiablePresentation {
  '@context': unknown;
  type: 'VerifiablePresentation';
  verifiableCredential: jsonld.NodeObject[];
}

export type ZkTerm = ZkSubject | ZkPredicate | ZkObject;
export type ZkSubject = sparqljs.IriTerm | sparqljs.BlankTerm;
export type ZkPredicate = sparqljs.IriTerm;
export type ZkObject =
  | sparqljs.IriTerm
  | sparqljs.BlankTerm
  | sparqljs.LiteralTerm;

type ZkSubjectBgp = ZkSubject | sparqljs.VariableTerm;
type ZkPredicateBgp = ZkPredicate | sparqljs.VariableTerm;
type ZkObjectBgp = ZkObject | sparqljs.VariableTerm;
export interface ZkTriplePattern {
  subject: ZkSubjectBgp;
  predicate: ZkPredicateBgp;
  object: ZkObjectBgp;
}

export interface IdentifyVcsResultType {
  extendedSolution: RDF.Bindings;
  vcGraphIdToBgpTriples: Map<string, ZkTriplePattern[]>;
}

export interface ParsedSparqlQuery {
  vars: sparqljs.VariableTerm[] | [sparqljs.Wildcard];
  parsedQuery: sparqljs.SelectQuery | sparqljs.AskQuery;
}

export interface ParsedQuery {
  vars: sparqljs.VariableTerm[] | [sparqljs.Wildcard];
  bgp: ZkTriplePattern[];
  notBgps: sparqljs.Pattern[];
  prefixes: Record<string, string>;
}

export interface RevealedQuads {
  revealedQuads: RDF.Quad[];
  anonymizedQuads: RDF.Quad[];
}

export interface VpSource {
  vcDocument: RDF.Quad[];
  vcProofs: RDF.Quad[][];
  anonymizedDocument: RDF.Quad[];
  deanonMap: Map<string, ZkTerm>;
}

export interface RevealedData {
  revealedVariables: string[];
  revealedSolutions: RDF.Bindings[];
  vpSourcesArray: VpSource[][];
}

interface JsonBindingsUriType {
  type: 'uri';
  value: string;
}
interface JsonBindingsLiteralType {
  type: 'literal';
  value: string;
  'xml:lang'?: string;
  datatype?: string;
}
interface JsonBindingsBnodeType {
  type: 'bnode';
  value: string;
}
export type JsonBindingsType =
  | JsonBindingsUriType
  | JsonBindingsLiteralType
  | JsonBindingsBnodeType;
export interface JsonResults {
  head: {
    vars: string[];
  };
  results: {
    bindings: Array<Record<string, JsonBindingsType>>;
  };
}
