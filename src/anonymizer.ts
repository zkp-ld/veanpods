import type * as RDF from '@rdfjs/types';
import { nanoid } from 'nanoid';
import { type DataFactory } from 'rdf-data-factory';
import type sparqljs from 'sparqljs';
import {
  type ZkObject,
  type ZkPredicate,
  type ZkSubject,
  type ZkTerm,
  type ZkTripleBgp,
} from './types';
import { isZkObject, isZkPredicate, isZkSubject } from './utils.js';

const ANONI_PREFIX = 'https://zkp-ld.org/.well-known/genid/anonymous/iri#';
const ANONB_PREFIX = 'https://zkp-ld.org/.well-known/genid/anonymous/bnid#';
const ANONL_PREFIX = 'https://zkp-ld.org/.well-known/genid/anonymous/literal#';
const NANOID_LEN = 6;

export class Anonymizer {
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

  private readonly _genKey = (val: ZkTerm): string =>
    val.termType === 'Literal'
      ? `${val.value}:${nanoid(NANOID_LEN)}`
      : `${val.value}`;

  anonymize = (val: ZkSubject | ZkPredicate): sparqljs.IriTerm => {
    const key = this._genKey(val);
    let anon: sparqljs.IriTerm;
    if (val.termType === 'NamedNode') {
      const result = this.iriToAnonMap.get(key);
      if (result !== undefined) {
        return result;
      }
      const anonIri = `${ANONI_PREFIX}${nanoid(NANOID_LEN)}`;
      anon = this.df.namedNode(anonIri) as sparqljs.IriTerm;
      this.iriToAnonMap.set(key, anon);
      this.anonToTerm.set(anonIri, val);
    } else {
      const result = this.bnodeToAnonMap.get(key);
      if (result !== undefined) {
        return result;
      }
      const anonBnid = `${ANONB_PREFIX}${nanoid(NANOID_LEN)}`;
      anon = this.df.namedNode(anonBnid) as sparqljs.IriTerm;
      this.bnodeToAnonMap.set(key, anon);
      this.anonToTerm.set(anonBnid, val);
    }

    return anon;
  };

  get = (val: ZkSubject | ZkPredicate): sparqljs.IriTerm | undefined => {
    const key = this._genKey(val);
    if (val.termType === 'NamedNode') {
      return this.iriToAnonMap.get(key);
    } else {
      return this.bnodeToAnonMap.get(key);
    }
  };

  anonymizeObject = (val: ZkObject): ZkObject => {
    if (val.termType === 'NamedNode' || val.termType === 'BlankNode') {
      return this.anonymize(val);
    }
    const key = this._genKey(val);
    const result = this.literalToAnonMap.get(key);
    if (result !== undefined) {
      return result;
    }
    const anonLiteral = `${ANONL_PREFIX}${nanoid(NANOID_LEN)}`;
    const languageOrDatatype =
      val.language !== '' ? val.language : val.datatype;
    const anon = this.df.literal(
      anonLiteral,
      languageOrDatatype
    ) as sparqljs.LiteralTerm;
    this.literalToAnonMap.set(key, anon);
    this.anonToTerm.set(anonLiteral, val);

    return anon;
  };

  getObject = (val: ZkObject): ZkObject | undefined => {
    const key = this._genKey(val);
    if (val.termType === 'NamedNode' || val.termType === 'BlankNode') {
      return this.get(val);
    } else {
      return this.literalToAnonMap.get(key);
    }
  };
}

export const anonymizeQuad = (
  bgpTriples: ZkTripleBgp[],
  vars: sparqljs.VariableTerm[],
  bindings: RDF.Bindings,
  df: DataFactory<RDF.Quad>,
  anonymizer: Anonymizer
): RDF.Quad[] =>
  bgpTriples.flatMap((triple) => {
    let subject: RDF.Term | undefined;
    if (triple.subject.termType !== 'Variable') {
      subject = triple.subject;
    } else if (vars.some((v) => v.value === triple.subject.value)) {
      subject = bindings.get(triple.subject);
    } else {
      const val = bindings.get(triple.subject);
      if (val !== undefined && isZkSubject(val)) {
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
      if (val !== undefined && isZkPredicate(val)) {
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
      return [df.quad(subject, predicate, object, graph)];
    } else {
      return [];
    }
  });
