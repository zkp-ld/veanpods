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

export interface IdentifyCredsResultType {
  extendedSolution: RDF.Bindings;
  graphIriToBgpTriple: Map<string, ZkTripleBgp[]>;
}

export type ParsedQuery = sparqljs.SelectQuery | sparqljs.AskQuery;

export interface VarsAndParsedQuery {
  requiredVars: sparqljs.VariableTerm[] | [sparqljs.Wildcard];
  parsedQuery: ParsedQuery;
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
  extendedSolutions: RDF.Bindings[];
  revealedCredsArray: Array<Map<string, RevealedCreds>>;
  requiredVars: sparqljs.VariableTerm[] | [sparqljs.Wildcard];
  anonToTerm: Map<string, ZkTerm>;
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
