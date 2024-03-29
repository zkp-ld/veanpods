import type * as RDF from '@rdfjs/types';
import {
  BbsTermwiseSignatureProof2021,
  verifyProofMulti,
  type VerifyProofMultiResult,
} from '@zkp-ld/rdf-signatures-bbs';
import jsonld from 'jsonld';
import jsigs from 'jsonld-signatures';
import { MemoryLevel } from 'memory-level';
import { Quadstore } from 'quadstore';
import { Engine } from 'quadstore-comunica';
import { DataFactory } from 'rdf-data-factory';
import { it, describe, expect } from 'vitest';
import { customLoader } from '../data/index.js';
import { processQuery } from '../processor.js';
import { type VerifiablePresentation } from '../types';

// built-in JSON-LD contexts and sample VCs
const documentLoader = customLoader;

// setup quadstore
const backend = new MemoryLevel();
const df = new DataFactory();
const store = new Quadstore({ backend, dataFactory: df });
const engine = new Engine(store);
await store.open();

// VCs for test
const testVcs = [
  {
    '@id': 'urn:graph:http://example.org/vaccinationCredential/01',
    '@graph': {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://zkp-ld.org/bbs-termwise-2021.jsonld',
        'https://schema.org',
        {
          Vaccination: 'http://example.org/vocab/Vaccination',
          isPatientOf: 'http://example.org/vocab/isPatientOf',
          lotNumber: 'http://example.org/vocab/lotNumber',
          vaccinationDate: {
            '@id': 'http://example.org/vocab/vaccinationDate',
            '@type': 'xsd:dateTime',
          },
          vaccine: {
            '@id': 'http://example.org/vocab/vaccine',
            '@type': '@id',
          },
        },
      ],
      id: 'http://example.org/vaccinationCredential/01',
      type: 'VerifiableCredential',
      issuer: 'did:example:issuer1',
      issuanceDate: '2022-01-01T00:00:00Z',
      expirationDate: '2025-01-01T00:00:00Z',
      credentialSubject: {
        id: 'did:example:xyz',
        type: 'Person',
        name: 'John Smith',
        isPatientOf: {
          type: 'Vaccination',
          id: 'http://example.org/vaccination/01',
          vaccinationDate: '2022-01-01T00:00:00Z',
          lotNumber: '0000001',
          vaccine: 'http://example.org/vaccine/987',
        },
      },
      proof: {
        '@context': 'https://zkp-ld.org/bbs-termwise-2021.jsonld',
        type: 'BbsTermwiseSignature2021',
        created: '2023-02-09T09:35:07Z',
        verificationMethod: 'did:example:issuer1#bbs-bls-key1',
        proofPurpose: 'assertionMethod',
        proofValue:
          'mA9oePddXRZK1dTCt9iJOAPd9WabAW0rThUIP6RoLbUdPG1L5pPnRUG9BBpnFuzAZk9X1b6jApMKYEdL4Dn7/FYWZeJckHxW9vz+UVH1S7IfQDGkcW3zuR3eEVPpOot/KY1akOy29JVcl2rkkS5UVw==',
      },
    },
  },
  {
    '@id': 'urn:graph:http://example.org/vaccinationCredential/04',
    '@graph': {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://zkp-ld.org/bbs-termwise-2021.jsonld',
        'https://schema.org',
        {
          Vaccination: 'http://example.org/vocab/Vaccination',
          isPatientOf: 'http://example.org/vocab/isPatientOf',
          lotNumber: 'http://example.org/vocab/lotNumber',
          vaccinationDate: {
            '@id': 'http://example.org/vocab/vaccinationDate',
            '@type': 'xsd:dateTime',
          },
          vaccine: {
            '@id': 'http://example.org/vocab/vaccine',
            '@type': '@id',
          },
        },
      ],
      id: 'http://example.org/vaccinationCredential/04',
      type: 'VerifiableCredential',
      issuer: 'did:example:issuer1',
      issuanceDate: '2022-04-04T00:00:00Z',
      expirationDate: '2025-04-04T00:00:00Z',
      credentialSubject: {
        id: 'did:example:xyz',
        type: 'Person',
        name: 'John Smith',
        isPatientOf: {
          type: 'Vaccination',
          id: 'http://example.org/vaccination/04',
          vaccinationDate: '2022-04-04T00:00:00Z',
          lotNumber: '1111111',
          vaccine: 'http://example.org/vaccine/987',
        },
      },
      proof: {
        '@context': 'https://zkp-ld.org/bbs-termwise-2021.jsonld',
        type: 'BbsTermwiseSignature2021',
        created: '2023-02-03T09:46:55Z',
        verificationMethod: 'did:example:issuer1#bbs-bls-key1',
        proofPurpose: 'assertionMethod',
        proofValue:
          'srl0BzpD2zCy9iV6beV82zU+F6WnBSFiL7uERojkUNS7K3D1HUNVLlwfAOVvruHIU5PX0qbq1fW7vEz2KjQz8V987tzyNCMBfBv/uJ9/ovQf1iLSF+l8qAwiHWoQcflsBWEB2oBljfaRAFAGnZg1NA==',
      },
    },
  },
  {
    '@id': 'urn:graph:http://example.org/vaccineInfoCredentials/987',
    '@graph': {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://zkp-ld.org/bbs-termwise-2021.jsonld',
        'https://schema.org',
        {
          Vaccine: 'http://example.org/vocab/Vaccine',
        },
      ],
      id: 'http://example.org/vaccineInfoCredentials/987',
      type: 'VerifiableCredential',
      issuer: 'did:example:issuer2',
      issuanceDate: '2020-01-01T00:00:00Z',
      expirationDate: '2023-12-31T00:00:00Z',
      credentialSubject: {
        id: 'http://example.org/vaccine/987',
        type: 'Vaccine',
        name: 'AwesomeVaccine',
        manufacturer: {
          id: 'http://example.org/awesomeCompany',
        },
        status: 'active',
      },
      proof: {
        '@context': 'https://zkp-ld.org/bbs-termwise-2021.jsonld',
        type: 'BbsTermwiseSignature2021',
        created: '2023-02-03T09:49:25Z',
        verificationMethod: 'did:example:issuer2#bbs-bls-key1',
        proofPurpose: 'assertionMethod',
        proofValue:
          'r3FbeXqzeJe0pSIK3fxwmXXRYOcphcFmF5wSPfo96FdZCch4ZtiwjWH015dZsqvTM2kraU3ah7Dt/bLfgnfYZCrU3blXeROPceBV8P7vJJMAlT9MABRzWWDbaRe/weL+kMWEDNRxcpIXuFPt09WtQg==',
      },
    },
  },
];

// store initial documents
const scope = await store.initScope(); // for preventing blank node collisions
const quads = (await jsonld.toRDF(testVcs, { documentLoader })) as RDF.Quad[];
await store.multiPut(quads, { scope });

// BBS+ suite
const suite = new BbsTermwiseSignatureProof2021({
  useNativeCanonize: false,
});

// utility function
const verifyVP = async (
  vp: VerifiablePresentation
): Promise<VerifyProofMultiResult> => {
  // verify derived VCs in VP
  const derivedVcs = vp.verifiableCredential;
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const verified = await verifyProofMulti(derivedVcs, {
    suite,
    documentLoader,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    purpose: new jsigs.purposes.AssertionProofPurpose(),
  });

  return verified as VerifyProofMultiResult;
};

describe('processQuery', () => {
  it('should return query results and VPs to the simple SELECT query without FILTER', async () => {
    const query = `
      PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
      PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
      PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
      PREFIX s: <http://schema.org/>
      PREFIX : <http://example.org/vocab/>

      SELECT ?date WHERE {
        ?s a s:Person .
        ?s :isPatientOf ?ev .
        ?ev :vaccinationDate ?date .
        ?ev :vaccine ?vac .
        ?vac s:status "active" .
      }
    `;

    // run zk-SPARQL query
    const result = await processQuery(query, store, df, engine);
    if ('error' in result) {
      throw new Error('processQuery returns error');
    }

    // check resulted variables
    expect(result.head).toEqual({
      vars: ['date', 'vp'],
    });

    expect(result.results.bindings).toHaveLength(4);

    for (const bindings of result.results.bindings) {
      // validate `date`
      const date = bindings.date;
      expect(date.type).toBe('literal');
      if (date.type !== 'literal') {
        throw new Error('date should be literal');
      }
      expect(date.datatype).toBe('http://www.w3.org/2001/XMLSchema#dateTime');
      expect(['2022-01-01T00:00:00Z', '2022-04-04T00:00:00Z']).toContain(
        date.value
      );

      // verify VP
      const vp = JSON.parse(bindings.vp.value) as VerifiablePresentation;
      const verified = await verifyVP(vp);
      expect(verified.verified).toBeTruthy();

      // TODO: check if VP is valid for query result
    }
  });

  it('should return query results and VPs to the simple SELECT query with FILTER', async () => {
    const query = `
      PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
      PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
      PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
      PREFIX s: <http://schema.org/>
      PREFIX : <http://example.org/vocab/>

      SELECT ?date WHERE {
        ?s a s:Person .
        ?s :isPatientOf ?ev .
        ?ev :vaccinationDate ?date .
        ?ev :vaccine ?vac .
        ?vac s:status "active" .
        FILTER ( ?date > "2022-03-31"^^xsd:dateTime )
      }
    `;

    // run zk-SPARQL query
    const result = await processQuery(query, store, df, engine);
    if ('error' in result) {
      throw new Error('processQuery returns error');
    }

    // check resulted variables
    expect(result.head).toEqual({
      vars: ['date', 'vp'],
    });

    expect(result.results.bindings).toHaveLength(2);

    for (const bindings of result.results.bindings) {
      // validate `date`
      const date = bindings.date;
      expect(date.type).toBe('literal');
      if (date.type !== 'literal') {
        throw new Error('date should be literal');
      }
      expect(date.datatype).toBe('http://www.w3.org/2001/XMLSchema#dateTime');
      expect(date.value).toEqual('2022-04-04T00:00:00Z');

      // verify VP
      const vp = JSON.parse(bindings.vp.value) as VerifiablePresentation;
      const verified = await verifyVP(vp);
      expect(verified.verified).toBeTruthy();

      // TODO: check if VP is valid for query result
    }
  });

  it('should return query results and VPs to the simple SELECT query with wildcard and FILTER', async () => {
    const query = `
      PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
      PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
      PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
      PREFIX s: <http://schema.org/>
      PREFIX : <http://example.org/vocab/>

      SELECT * WHERE {
        ?s a s:Person .
        ?s :isPatientOf ?ev .
        ?ev :vaccinationDate ?date .
        ?ev :vaccine ?vac .
        ?vac s:status "active" .
        FILTER ( ?date > "2022-03-31"^^xsd:dateTime )
      }
    `;

    // run zk-SPARQL query
    const result = await processQuery(query, store, df, engine);
    if ('error' in result) {
      throw new Error('processQuery returns error');
    }

    // check resulted variables
    expect(result.head).toEqual({
      vars: ['date', 'ev', 's', 'vac', 'vp'],
    });

    expect(result.results.bindings).toHaveLength(2);

    for (const bindings of result.results.bindings) {
      // validate `date`
      const date = bindings.date;
      expect(date.type).toBe('literal');
      if (date.type !== 'literal') {
        throw new Error('date should be literal');
      }
      expect(date.datatype).toBe('http://www.w3.org/2001/XMLSchema#dateTime');
      expect(date.value).toEqual('2022-04-04T00:00:00Z');

      // TODO: validate other bindings

      // verify VP
      const vp = JSON.parse(bindings.vp.value) as VerifiablePresentation;
      const verified = await verifyVP(vp);
      expect(verified.verified).toBeTruthy();

      // TODO: check if VP is valid for query result
    }
  });

  it('should return no results to the simple SELECT query with out-of-range FILTER', async () => {
    const query = `
      PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
      PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
      PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
      PREFIX s: <http://schema.org/>
      PREFIX : <http://example.org/vocab/>

      SELECT ?date WHERE {
        ?s a s:Person .
        ?s :isPatientOf ?ev .
        ?ev :vaccinationDate ?date .
        ?ev :vaccine ?vac .
        ?vac s:status "active" .
        FILTER ( ?date > "9999-12-31"^^xsd:dateTime ) # out-of-range
      }
    `;

    // run zk-SPARQL query
    const result = await processQuery(query, store, df, engine);
    if ('error' in result) {
      throw new Error('processQuery returns error');
    }

    // check resulted variables
    expect(result.head).toEqual({
      vars: ['date', 'vp'],
    });

    expect(result.results.bindings).toHaveLength(0);
  });

  it('should return query results and VPs to the simple ASK query without FILTER', async () => {
    const query = `
      PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
      PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
      PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
      PREFIX s: <http://schema.org/>
      PREFIX : <http://example.org/vocab/>

      ASK WHERE {
        ?s a s:Person .
        ?s :isPatientOf ?ev .
        ?ev :vaccinationDate ?date .
        ?ev :vaccine ?vac .
        ?vac s:status "active" .
      }
    `;

    // run zk-SPARQL query
    const result = await processQuery(query, store, df, engine);
    if ('error' in result) {
      throw new Error('processQuery returns error');
    }

    // check resulted variables
    expect(result.head).toEqual({
      vars: ['vp'],
    });

    expect(result.results.bindings).toHaveLength(4);

    for (const bindings of result.results.bindings) {
      // verify VP
      const vp = JSON.parse(bindings.vp.value) as VerifiablePresentation;
      const verified = await verifyVP(vp);
      expect(verified.verified).toBeTruthy();

      // TODO: check if VP is valid for query result
    }
  });

  it('should return query results and VPs to the simple ASK query with FILTER', async () => {
    const query = `
      PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
      PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
      PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
      PREFIX s: <http://schema.org/>
      PREFIX : <http://example.org/vocab/>

      ASK WHERE {
        ?s a s:Person .
        ?s :isPatientOf ?ev .
        ?ev :vaccinationDate ?date .
        ?ev :vaccine ?vac .
        ?vac s:status "active" .
        FILTER ( ?date > "2022-03-31"^^xsd:dateTime )
      }
    `;

    // run zk-SPARQL query
    const result = await processQuery(query, store, df, engine);
    if ('error' in result) {
      throw new Error('processQuery returns error');
    }

    // check resulted variables
    expect(result.head).toEqual({
      vars: ['vp'],
    });

    expect(result.results.bindings).toHaveLength(2);

    for (const bindings of result.results.bindings) {
      // verify VP
      const vp = JSON.parse(bindings.vp.value) as VerifiablePresentation;
      const verified = await verifyVP(vp);
      expect(verified.verified).toBeTruthy();

      // TODO: check if VP is valid for query result
    }
  });
});
