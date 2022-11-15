import jsonldSignatures from "jsonld-signatures";

import citizenVocab from "./context/citizen_vocab.json" assert { type: 'json' };
import credentialContext from "./context/credential_vocab.json" assert { type: 'json' };
import odrlContext from "./context/odrl.json" assert { type: 'json' };
import securityV3 from "./context/v3_unstable.json" assert { type: 'json' };
import securityV2 from "./context/security-v2.json" assert { type: 'json' };
import securityV1 from "./context/security-v1.json" assert { type: 'json' };
import bbsContext from "./context/bbs.json" assert { type: 'json' };
import jwsContext from "./context/jws.json" assert { type: 'json' };
import vcExampleContext from "./context/vc_example_vocab.json" assert { type: 'json' };
import schemaOrg from "./context/schemaOrg.json" assert { type: 'json' };
import bbsTermwiseContext from "./context/bbs-termwise-2021.json" assert { type: 'json' };

import exampleDidKey from "./data/did_example_489398593_test.json" assert { type: 'json' };
import exampleDidDoc from "./data/did_example_489398593.json" assert { type: 'json' };
import exampleDidb34Key from "./data/did_example_b34ca6cd37bbf23_test.json" assert { type: 'json' };
import exampleDidb34Doc from "./data/did_example_b34ca6cd37bbf23.json" assert { type: 'json' };
import exampleDid826Key from "./data/did_example_82612387612873_test.json" assert { type: 'json' };
import exampleDid826Doc from "./data/did_example_82612387612873.json" assert { type: 'json' };
import expExampleDidKey from "./data/exp_didkey_issuer1.json" assert { type: 'json' };
import expExampleDidDoc from "./data/exp_diddoc_issuer1.json" assert { type: 'json' };
import expExampleDidKey2 from "./data/exp_didkey_issuer2.json" assert { type: 'json' };
import expExampleDidDoc2 from "./data/exp_diddoc_issuer2.json" assert { type: 'json' };
import expExampleDidKey3 from "./data/exp_didkey_issuer3.json" assert { type: 'json' };
import expExampleDidDoc3 from "./data/exp_diddoc_issuer3.json" assert { type: 'json' };

const _prepareDocs = (obj: any): [string, string][] =>
  Object.entries(obj).map((e: [string, any]) => [
    e[0],
    JSON.stringify(e[1], null, 2),
  ]);

const _builtinDIDDocs: Record<string, any> = {
  "did:example:issuer1": expExampleDidDoc,
  "did:example:issuer1#bbs-bls-key1": expExampleDidKey,
  "did:example:issuer2": expExampleDidDoc2,
  "did:example:issuer2#bbs-bls-key1": expExampleDidKey2,
  "did:example:issuer3": expExampleDidDoc3,
  "did:example:issuer3#bbs-bls-key1": expExampleDidKey3,
  "did:example:489398593": exampleDidDoc,
  "did:example:489398593#test": exampleDidKey,
  "did:example:82612387612873": exampleDid826Doc,
  "did:example:82612387612873#test": exampleDid826Key,
  "did:example:b34ca6cd37bbf23": exampleDidb34Doc,
  "did:example:b34ca6cd37bbf23#test": exampleDidb34Key,
};
export const builtinDIDDocs = new Map(_prepareDocs(_builtinDIDDocs));

export const _builtinContexts: Record<string, any> = {
  "https://www.w3.org/2018/credentials/v1": credentialContext,
  "https://www.w3.org/2018/credentials/examples/v1": vcExampleContext,
  "https://www.w3.org/ns/odrl.jsonld": odrlContext,
  "https://zkp-ld.org/bbs-termwise-2021.jsonld": bbsTermwiseContext,
  "https://w3id.org/security/suites/bls12381-2020/v1": bbsContext,
  "https://w3id.org/security/suites/jws-2020/v1": jwsContext,
  "https://w3id.org/security/bbs/v1": bbsContext,
  "https://w3id.org/security/v3-unstable": securityV3,
  "https://w3id.org/security/v2": securityV2,
  "https://w3id.org/security/v1": securityV1,
  "https://w3id.org/citizenship/v1": citizenVocab,
  "https://schema.org": schemaOrg,
  "https://schema.org/": schemaOrg,
  "http://schema.org/": schemaOrg,
};
export const builtinContexts = new Map(_prepareDocs(_builtinContexts));

// const customDocLoader =
//   (documents: Map<string, any>) =>
//   (url: string): any => {
//     const context = documents.get(url);
//     if (context) {
//       return {
//         contextUrl: null, // this is for a context via a link header
//         document: context, // this is the actual document that was loaded
//         documentUrl: url, // this is the actual context URL after redirects
//       };
//     }

//     throw new Error(
//       `Error attempted to load document remotely, please cache '${url}'`
//     );
//   };

// export const customLoader = (documents: Map<string, any>) =>
//   customDocLoader(documents);

const documents = Object.assign(_builtinContexts, _builtinDIDDocs);
const customDocLoader =
  (url: string): any => {
    const context = documents[url];
    if (context) {
      return {
        contextUrl: null, // this is for a context via a link header
        document: context, // this is the actual document that was loaded
        documentUrl: url, // this is the actual context URL after redirects
      };
    }

    throw new Error(
      `Error attempted to load document remotely, please cache '${url}'`
    );
  };

export const customLoader = jsonldSignatures.extendContextLoader(customDocLoader);