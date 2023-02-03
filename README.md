# veanpods

**WORK IN PROGRESS**

**Experimental**: do not use in production

Verifiable and anonymous personal datastore supporting zk-SPARQL queries, based on Verifiable Credentials (VCs) and Verifiable Presentations (VPs) with BBS+ signatures.

## zk-SPARQL

TODO

## Examples

Assume that the datastore owner (VC Holder) have the following two VCs in their veanpods:

The first VC shows that a person, John Smith, got vaccinated on April 4th, 2022. The type of vaccine used here is identified by URI `http://example.org/vaccine/987`.

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://zkp-ld.org/bbs-termwise-2021.jsonld",
    "https://schema.org",
    {
      "Vaccination": "http://example.org/vocab/Vaccination",
      "isPatientOf": "http://example.org/vocab/isPatientOf",
      "lotNumber": "http://example.org/vocab/lotNumber",
      "vaccinationDate": {
        "@id": "http://example.org/vocab/vaccinationDate",
        "@type": "xsd:dateTime"
      },
      "vaccine": {
        "@id": "http://example.org/vocab/vaccine",
        "@type": "@id"
      }
    }
  ],
  "id": "http://example.org/vaccinationCredential/04",
  "type": "VerifiableCredential",
  "issuer": "did:example:issuer1",
  "issuanceDate": "2022-04-04T00:00:00Z",
  "expirationDate": "2025-04-04T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:xyz",
    "type": "Person",
    "name": "John Smith",
    "isPatientOf": {
      "type": "Vaccination",
      "id": "http://example.org/vaccination/04",
      "vaccinationDate": "2022-04-04T00:00:00Z",
      "lotNumber": "1111111",
      "vaccine": "http://example.org/vaccine/987"
    }
  },
  "proof": {
    "@context": "https://zkp-ld.org/bbs-termwise-2021.jsonld",
    "type": "BbsTermwiseSignature2021",
    "created": "2023-02-03T09:46:55Z",
    "verificationMethod": "did:example:issuer1#bbs-bls-key1",
    "proofPurpose": "assertionMethod",
    "proofValue": "srl0BzpD2zCy9iV6beV82zU+F6WnBSFiL7uERojkUNS7K3D1HUNVLlwfAOVvruHIU5PX0qbq1fW7vEz2KjQz8V987tzyNCMBfBv/uJ9/ovQf1iLSF+l8qAwiHWoQcflsBWEB2oBljfaRAFAGnZg1NA=="
  }
}
```

The second VC gives us the details of the vaccine identified by `http://example.org/vaccine/987`, that is, its name, its manufacturer, and its approval status.

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://zkp-ld.org/bbs-termwise-2021.jsonld",
    "https://schema.org",
    {
      "Vaccine": "http://example.org/vocab/Vaccine"
    }
  ],
  "id": "http://example.org/vaccineInfoCredentials/987",
  "type": "VerifiableCredential",
  "issuer": "did:example:issuer2",
  "issuanceDate": "2020-01-01T00:00:00Z",
  "expirationDate": "2023-12-31T00:00:00Z",
  "credentialSubject": {
    "id": "http://example.org/vaccine/987",
    "type": "Vaccine",
    "name": "AwesomeVaccine",
    "manufacturer": {
      "id": "http://example.org/awesomeCompany"
    },
    "status": "active"
  },
  "proof": {
    "@context": "https://zkp-ld.org/bbs-termwise-2021.jsonld",
    "type": "BbsTermwiseSignature2021",
    "created": "2023-02-03T09:49:25Z",
    "verificationMethod": "did:example:issuer2#bbs-bls-key1",
    "proofPurpose": "assertionMethod",
    "proofValue": "r3FbeXqzeJe0pSIK3fxwmXXRYOcphcFmF5wSPfo96FdZCch4ZtiwjWH015dZsqvTM2kraU3ah7Dt/bLfgnfYZCrU3blXeROPceBV8P7vJJMAlT9MABRzWWDbaRe/weL+kMWEDNRxcpIXuFPt09WtQg=="
  }
}
```

These two credentials are represented as the following RDF dataset (represented in N-Quads):

```n-quads
# VC1
<http://example.org/vaccinationCredential/04> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vaccinationCredential/04> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:xyz> .
<did:example:xyz> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:xyz> <http://schema.org/name> "John Smith" .
<did:example:xyz> <http://example.org/vocab/isPatientOf> <http://example.org/vaccination/04> .
<http://example.org/vaccination/04> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
<http://example.org/vaccination/04> <http://example.org/vocab/vaccinationDate> "2022-04-04T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vaccination/04> <http://example.org/vocab/vaccine> <http://example.org/vaccine/987> .
# ... proof and some quads are omitted

# VC2
<http://example.org/vaccineInfoCredentials/987> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vaccineInfoCredentials/987> <https://www.w3.org/2018/credentials#credentialSubject> <http://example.org/vaccine/987> .
<http://example.org/vaccine/987> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccine> .
<http://example.org/vaccine/987> <http://schema.org/name> "AwesomeVaccine" .
<http://example.org/vaccine/987> <http://schema.org/manufacturer> <http://example.org/awesomeCompany> .
<http://example.org/vaccine/987> <http://schema.org/status> "active" .
# ... proof and some quads are omitted
```

Then, imagine that an officer (verifier) asks John Smith to show that he has already got vaccinated after, say, 2022-03-31, and the vaccine used there is authorized as "active". The officer can express this requirement as zk-SPARQL query as follows:

```sparql
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
```

Our zk-SPARQL endpoint can process this query and respond with the following query results in the zk-SPARQL Query Results JSON Format:

```json
{
  "head": { "vars": [ "date", "vp" ] },
  "results": {
    "bindings": [
      {
        "date": {
          "type": "literal",
          "value": "2022-04-04T00:00:00Z",
          "datatype": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "vp": {
          "type": "literal",
          "value": "{{{VP as JSON string}}}"
        }
      }
    ]
  }
}
```

This results are typically rendered as the following human-friendly table:

| date                 | vp                      |
|----------------------|-------------------------|
| 2022-04-04T00:00:00Z | {{{VP as JSON string}}} |

`{{{VP as JSON string}}}` part consists of the following VP:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://zkp-ld.org/bbs-termwise-2021.jsonld",
    "https://schema.org"
  ],
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://zkp-ld.org/bbs-termwise-2021.jsonld",
        "https://schema.org"
      ],
      "id": "http://example.org/vaccinationCredential/04",
      "type": "VerifiableCredential",
      "credentialSubject": {
        "id": "anoni:IGDDf_",
        "type": "Person",
        "http://example.org/vocab/isPatientOf": {
          "id": "anoni:LnCuad",
          "http://example.org/vocab/vaccinationDate": {
            "type": "xsd:dateTime",
            "@value": "2022-04-04T00:00:00Z"
          },
          "http://example.org/vocab/vaccine": {
            "id": "anoni:R28Rl6"
          }
        }
      },
      "expirationDate": "2025-04-04T00:00:00Z",
      "issuanceDate": "2022-04-04T00:00:00Z",
      "issuer": "did:example:issuer1",
      "proof": {
        "type": "BbsTermwiseSignatureProof2021",
        "created": "2023-02-03T09:46:55Z",
        "nonce": "3ZH/2wGdxjFM/lcbVfDY6jPTWb7hu0qmj5sDk0OFU0RnkROFszYqeorAIm4iqRdaPfg=",
        "proofPurpose": "assertionMethod",
        "proofValue": "WzAsMSwyLDMsMTEsMTIsMTMsMTQsMTUsNCw2LDgsOV0=.owAYQAFZA9yih/bHL/IQ6fBl7sTEYLghDiSUBfvRu1k5muindmZFqfFrBQNAB1r3moFieNIX4LevHuoWFiAmEjLjwo+TOLxuAn+W2cqSfRvALboUcAoxrgG901zVsghlZGKw45LIQmW1RPVRkKLsKSwz0Gig90GS7N9LWSSqWojewYsp7ArTdpxbF7q51/scxDAXxQwu55EAAAB0kdBRQtkBaVXJoNNV3CdlsXCW2+g9JnLioSbeMd+Hz4EvSYEVId9Gq9HaSpgmi2vWAAAAAjVrDsl4COHkGPVZHVgIU3AZd07ngnDhwvEBkhfLzEfjXAn64GlbTmRI8s+crF1YHmd8M8euvuqbhpuEWlfoCam3JWf0dzGeQ342tZsLO7syLOaVdFunQnYykTdSfeZltCFn80KW3S+OosfKYjHH2qoAAAAVFUep3Gllly9aLtAkmOk977cGTt98/2PlugrCt1my8EEQeXeCG7v3SgfVSr7tiAq5ycwIvD0A7FpfYKnRSQpjVQjKkkPI14XjTaoh/uosRnhtaV/43MPe3izsiysJSYI5Mt++V+ISf/Z+P+qRxJF7f8YKvYF2jzlLPs7ZWh76Toc2U0PY3uRoDz7njH40nVPctr1coW8EtM4sWwL/8v8YkTWsjo8Kx4ZLwVivMwhifGVL8JKnCfxgt/+KSsEmZVUKPWsXSUTmaAZSdzaHiHqWgUKBQd2BKrbh8tN9hhRNW0RVVpnLJsKjomf7vBy+/gYI/CmT+eacNXVic9+5cKWG3QjKkkPI14XjTaoh/uosRnhtaV/43MPe3izsiysJSYI5cb09Gs9+OTjvLBJxiRlrlcrKHlUVCGcRmcGQqPPr34Vrf4qhZuBTx9UiY/ZFLE5VfC6v+le82hGWVrxfGxhJVzwt1xKRZzVu9eZHgiWoPJKxZak3RzfiwJ7moZlK8JA5VvO/A3E8XRM6xAFEId94asV+RSWTzgXetZNWgYNeQp0y375X4hJ/9n4/6pHEkXt/xgq9gXaPOUs+ztlaHvpOhzLfvlfiEn/2fj/qkcSRe3/GCr2Bdo85Sz7O2Voe+k6Hc6gJ0wHzXz382Yl/ayVdAVQ2gL1bZJ9CiUwM1FRgBG8YlK2+pfbIN4J+nLAvWH+WrZaTjCwZo8yQrM3v/1ZbqzGJuUJWqNsn/DhsLJexP2BDj1/5nhwfZRh+pJ8Fs2ODQKh79vDQMay4sydbMXsWiLjXLTVrU9iMa5MJwe+PkII5DpTrvt61Y/2U1ehs0EMLbckLCRk9bizILehLB7ZXmgjKkkPI14XjTaoh/uosRnhtaV/43MPe3izsiysJSYI5AoA=",
        "verificationMethod": "did:example:issuer1#bbs-bls-key1"
      }
    },
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://zkp-ld.org/bbs-termwise-2021.jsonld",
        "https://schema.org"
      ],
      "id": "http://example.org/vaccineInfoCredentials/987",
      "type": "VerifiableCredential",
      "credentialSubject": {
        "id": "anoni:R28Rl6",
        "status": "active"
      },
      "expirationDate": "2023-12-31T00:00:00Z",
      "issuanceDate": "2020-01-01T00:00:00Z",
      "issuer": "did:example:issuer2",
      "proof": {
        "type": "BbsTermwiseSignatureProof2021",
        "created": "2023-02-03T09:49:25Z",
        "nonce": "3ZH/2wGdxjFM/lcbVfDY6jPTWb7hu0qmj5sDk0OFU0RnkROFszYqeorAIm4iqRdaPfg=",
        "proofPurpose": "assertionMethod",
        "proofValue": "WzAsMSwyLDMsOCw5LDEwLDExLDEyLDZd.owAYNAFZAzypSzCSFGIHvFpYYcHsnIlRAcf6YElheBP8BhQE57DNt3fz68JNJiaqjw8VypkKhA2YPUuKwznV6QeY5X/3UE9JKYlM8Mw/slSa65QFNNHczcacunssPRcQuSenpAW6QnyCxGW1gop3JeJDLUpnBP3Dfx5p/wWG04s03mnaFFeRacaqNUfGNpCIKoMCfpaZqU8AAAB0svc+8XNpEEc3me0AhIVw+C1i4PLaLZiEecxULRns4i40uPvPpIxCC9Xb1eA7ThDHAAAAAjEltT3eDTVubX2Et8UPc/ABYs138cGx/lg9MGj+gl/pF85dRhamt1ymXYRUjel/X8zHzK7YYFgneTfD2RO5hsynZfT+q/rXO0wQm6rq9fu7fTiVqz38lm3kPF8A388lNxvQs3exVFvtaZPlCw8DA20AAAAQDmGkli1Vd8UrsJYEiw9DtDZyJLfzt9dAYVBBvh7OpG8d2qdm72nyP9BZs+RCZxXukwvVABfjhHGE9VWk+LBH+TBS7cgG62ikvLc4vZKrF+auREIiczmBgSfG7ULH8hieaKTQYAE7E86I3fyHH5u53qB97r1A3PknUxAypXtqYBFkgY2p0c5O09wuTEQ8ILtyF4WGpLgLqUD6kRclYgplWCiOsV1cVWeTVgBRyD0uKadEztsLZYexkJZ5k4FIhJcyMq1mWOJFLxiIriwW9VIAiJdF950qE4/hafpJdkJYalZmlPDnltUOSzL0VIgV1V4L28qtFE/cmakbyFQUfVgG4AXBL6+V5u/cu/3SGcwGhr23T8otlECiiGDbg4zv2lHKXlqcAiRXE36YHrjBACk7qGY4e5AqmruSyodMUoZAWvVzqAnTAfNfPfzZiX9rJV0BVDaAvVtkn0KJTAzUVGAEbwzqV+xABqYW1JftouleqKRXY7n62ilaPAZDlg80wG5pMk5nm9clTF2KMtJGSsqLDY5H0eJyBd3GraLzy6DJUAUhYkfimf9ciVn4pQbk9JrU3f7B4GWBLkK1i2Jms3UHblsTQ0eN5yyFdFf7uiJWjPHuYhIjKGIA3zXM4UW2Bizbc6gJ0wHzXz382Yl/ayVdAVQ2gL1bZJ9CiUwM1FRgBG8CgA==",
        "verificationMethod": "did:example:issuer2#bbs-bls-key1"
      }
    }
  ]
}
```

This VP itself is JSON-LD document so that the officer (verifier) can transform it into the following RDF dataset:

```n-quads
# derived from VC1
<http://example.org/vaccinationCredential/04> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:b1 .
<http://example.org/vaccinationCredential/04> <https://www.w3.org/2018/credentials#credentialSubject> <https://zkp-ld.org/.well-known/genid/anonymous/iri#IGDDf_> _:b1 .
<https://zkp-ld.org/.well-known/genid/anonymous/iri#IGDDf_> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> _:b1 .
<https://zkp-ld.org/.well-known/genid/anonymous/iri#IGDDf_> <http://example.org/vocab/isPatientOf> <https://zkp-ld.org/.well-known/genid/anonymous/iri#LnCuad> _:b1 .
<https://zkp-ld.org/.well-known/genid/anonymous/iri#LnCuad> <http://example.org/vocab/vaccinationDate> "2022-04-04T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:b1 .
<https://zkp-ld.org/.well-known/genid/anonymous/iri#LnCuad> <http://example.org/vocab/vaccine> <https://zkp-ld.org/.well-known/genid/anonymous/iri#R28Rl6> _:b1 .
# ... proof and some quads are omitted

# derived from VC2
<http://example.org/vaccineInfoCredentials/987> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:b4 .
<http://example.org/vaccineInfoCredentials/987> <https://www.w3.org/2018/credentials#credentialSubject> <https://zkp-ld.org/.well-known/genid/anonymous/iri#R28Rl6> _:b4 .
<https://zkp-ld.org/.well-known/genid/anonymous/iri#R28Rl6> <http://schema.org/status> "active" _:b4 .
# ... proof and some quads are omitted
```

Compared to the original N-Quads, we can see that some URIs are replaced with the pseudonymous values like `<https://zkp-ld.org/.well-known/genid/anonymous/iri#IGDDf_>` because they are not required to appear to answer to the zk-SPARQL query.

The officer (verifier) can execute their zk-SPARQL query against this N-Quads to check that this VP exactly includes the query result.
The officer (verifier) can also verify the VP's authenticity using BBS+ verification algorithm.
If both checks are passed, the officer can accept this zk-SPARQL query result as a verified result.
