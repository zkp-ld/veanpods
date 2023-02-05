import express from 'express';
import jsonld from 'jsonld';
import * as RDF from '@rdfjs/types';
import { MemoryLevel } from 'memory-level';
import { DataFactory } from 'rdf-data-factory';
import { Quadstore } from 'quadstore';
import { Engine } from 'quadstore-comunica';
import { processQuery, processSparqlQuery } from './utils.js';

// built-in JSON-LD contexts and sample VCs
import { customLoader, sampleVcs } from "./data/index.js";
const documentLoader = customLoader;

// setup quadstore
const backend = new MemoryLevel();
const df = new DataFactory();
const store = new Quadstore({ backend, dataFactory: df });
const engine = new Engine(store);
await store.open();

// store initial documents
const scope = await store.initScope();  // for preventing blank node collisions
const quads = await jsonld.toRDF(sampleVcs, { documentLoader }) as RDF.Quad[];
await store.multiPut(quads, { scope });

// setup express server
const app = express();
const port = 3000;
app.disable('x-powered-by');
app.listen(port, () => {
  console.log('started on port 3000');
});

// zk-SPARQL endpoint
app.get('/zk-sparql/', async (req, res, next) => {
  const query = req.query.query;
  if (typeof query !== "string") {
    return next(new Error("SPARQL query must be given as `query` parameter"))
  }
  const result = await processQuery(query, store, df, engine);
  if ('error' in result) {
    return next(new Error(result.error));
  }
  res.send(result);
});

// plain SPARQL endpoint (for debug)
app.get('/sparql/', async (req, res, next) => {
  // get query string
  const query = req.query.query;
  if (typeof query !== "string") {
    return next(new Error("SPARQL query must be given as `query` parameter"));
  }

  const result = await processSparqlQuery(query, engine);
  if (typeof result === "string") {
    return next(new Error(result));
  }
  res.send(result);
});

// // zk-SPARQL endpoint (fetch only)
// app.get('/zk-sparql/fetch', async (req, res, next) => {
//   // 1. parse zk-SPARQL query and execute SELECT on internal quadstore
//   const query = req.query.query;
//   if (typeof query !== 'string') {
//     return { 'error': 'SPARQL query must be given as `query` parameter' };
//   }
//   const queryResult = await fetch(query, store, df, engine);
//   if ('error' in queryResult) {
//     return next(new Error(queryResult.error));
//   }
//   const { requiredVars, extendedSolutions, revealedCredsArray, anonToTerm: _ } = queryResult;

//   // 2. generate VPs (without real proofs)
//   const vps: VP[] = [];
//   for (const creds of revealedCredsArray) {
//     // serialize derived VCs as JSON-LD documents
//     const derivedVCs: jsonld.NodeObject[] = [];
//     for (const [_credGraphIri, { anonymizedDoc, proofs }] of creds) {
//       // remove proof.proofValue
//       const proofQuads = proofs.flat().filter(
//         (quad) =>
//           quad.predicate.value !== `${SEC_PREFIX}proofValue`
//       );
//       // concat document and proofs
//       const anonymizedCred = anonymizedDoc.concat(proofQuads);
//       // add bnode prefix `_:` to blank node ids
//       const anonymizedCredWithBnodePrefix = addBnodePrefix(anonymizedCred);
//       // RDF to JSON-LD
//       const credJson = await jsonld.fromRDF(anonymizedCredWithBnodePrefix);
//       // to compact JSON-LD
//       const credJsonCompact = await jsonld.compact(credJson, CONTEXTS, { documentLoader });
//       // shape it to be a VC
//       const derivedVC = await jsonld.frame(credJsonCompact, VC_FRAME, { documentLoader });
//       derivedVCs.push(derivedVC);
//     }

//     // serialize VP
//     const vp = { ...VP_TEMPLATE };
//     vp['verifiableCredential'] = derivedVCs;
//     vps.push(vp);
//   }

//   // 3. add VPs (or VCs) to each corresponding solutions
//   const bindingsWithVPArray = extendedSolutions.map(
//     (extendedSolution, i) =>
//       extendedSolution.set('vp', df.literal(
//         `${JSON.stringify(vps[i], null, 2)}`,
//         df.namedNode(`${RDF_PREFIX}JSON`))));

//   // 4. send response
//   let jsonVars: string[];
//   if (isWildcard(requiredVars)) {
//     // SELECT * WHERE {...}
//     jsonVars = extendedSolutions.length >= 1 ? [...extendedSolutions[0].keys()].map((k) => k.value) : [''];
//   } else {
//     // SELECT ?s ?p ?o WHERE {...}
//     jsonVars = requiredVars.map((v) => v.value);
//   }
//   jsonVars.push('vp');
//   res.send(genJsonResults(jsonVars, bindingsWithVPArray));
// });
