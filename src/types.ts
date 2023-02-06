import jsonld from 'jsonld';
import sparqljs from 'sparqljs';
import * as RDF from '@rdfjs/types';

export type VP =
  {
    '@context': any;
    type: 'VerifiablePresentation';
    verifiableCredential: jsonld.NodeObject[];
  };

type ZkTermBgp = ZkSubjectBgp | ZkPredicateBgp | ZkObjectBgp;
type ZkSubjectBgp = sparqljs.IriTerm | sparqljs.VariableTerm;
type ZkPredicateBgp = sparqljs.IriTerm | sparqljs.VariableTerm;
type ZkObjectBgp = sparqljs.IriTerm | sparqljs.LiteralTerm | sparqljs.VariableTerm;
export interface ZkTripleBgp {
  subject: ZkSubjectBgp,
  predicate: ZkPredicateBgp,
  object: ZkObjectBgp,
};

export type ZkTerm = ZkSubject | ZkPredicate | ZkObject;
export type ZkSubject = sparqljs.IriTerm | sparqljs.BlankTerm;
export type ZkPredicate = sparqljs.IriTerm;
export type ZkObject = sparqljs.IriTerm | sparqljs.BlankTerm | sparqljs.LiteralTerm;

export type IdentifyCredsResultType = {
  extendedSolution: RDF.Bindings,
  graphIriToBgpTriple: Map<string, ZkTripleBgp[]>,
};

export type ParsedQuery = sparqljs.SelectQuery | sparqljs.AskQuery;

export type VarsAndParsedQuery = {
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

export interface FetchResult {
  extendedSolutions: RDF.Bindings[];
  revealedCredsArray: Map<string, RevealedCreds>[];
  requiredVars: sparqljs.VariableTerm[] | [sparqljs.Wildcard];
  anonToTerm: Map<string, ZkTerm>;
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
export type JsonBindingsType = JsonBindingsUriType | JsonBindingsLiteralType | JsonBindingsBnodeType;
export type JsonResults = {
  head: {
    vars: string[],
  },
  results: {
    bindings: {
      [k: string]: JsonBindingsType,
    }[]
  }
};
