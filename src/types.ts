import type * as RDF from '@rdfjs/types';
import type jsonld from 'jsonld';
import type sparqljs from 'sparqljs';

export interface VerifiablePresentation {
  '@context': unknown;
  type: 'VerifiablePresentation';
  verifiableCredential: jsonld.NodeObject[];
}

type ZkSubjectBgp = sparqljs.IriTerm | sparqljs.VariableTerm;
type ZkPredicateBgp = sparqljs.IriTerm | sparqljs.VariableTerm;
type ZkObjectBgp =
  | sparqljs.IriTerm
  | sparqljs.LiteralTerm
  | sparqljs.VariableTerm;
export interface ZkTripleBgp {
  subject: ZkSubjectBgp;
  predicate: ZkPredicateBgp;
  object: ZkObjectBgp;
}

export type ZkTerm = ZkSubject | ZkPredicate | ZkObject;
export type ZkSubject = sparqljs.IriTerm | sparqljs.BlankTerm;
export type ZkPredicate = sparqljs.IriTerm;
export type ZkObject =
  | sparqljs.IriTerm
  | sparqljs.BlankTerm
  | sparqljs.LiteralTerm;

export interface IdentifyVcsResultType {
  extendedSolution: RDF.Bindings;
  vcGraphIdToBgpTriple: Map<string, ZkTripleBgp[]>;
}

export interface ParsedSparqlQuery {
  requiredVars: sparqljs.VariableTerm[] | [sparqljs.Wildcard];
  parsedQuery: sparqljs.SelectQuery | sparqljs.AskQuery;
}

export interface ParsedQuery {
  requiredVars: sparqljs.VariableTerm[] | [sparqljs.Wildcard];
  bgpTriples: ZkTripleBgp[];
  where: sparqljs.Pattern[] | undefined;
  prefixes: Record<string, string>;
}

export interface RevealedQuads {
  revealedQuads: RDF.Quad[];
  anonymizedQuads: RDF.Quad[];
}

export interface RevealedCreds {
  wholeDoc: RDF.Quad[];
  anonymizedDoc: RDF.Quad[];
  proofs: RDF.Quad[][];
}

export interface InternalQueryResult {
  revealedSolutions: RDF.Bindings[];
  jsonVars: string[];
  revealedCredsArray: Array<Map<string, RevealedCreds>>;
  anonToTerm: Map<string, ZkTerm>;
}

export interface ExtendedSolutions {
  extendedSolutions: RDF.Bindings[];
  vcGraphVarAndBgpTriple: Array<[string, ZkTripleBgp]>;
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
