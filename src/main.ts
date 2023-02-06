import type * as RDF from '@rdfjs/types';
import express from 'express';
import jsonld from 'jsonld';
import { MemoryLevel } from 'memory-level';
import { Quadstore } from 'quadstore';
import { Engine } from 'quadstore-comunica';
import { DataFactory } from 'rdf-data-factory';
import { customLoader, sampleVcs } from './data/index.js';
import { processQuery } from './processor.js';
import { processSparqlQuery } from './utils.js';

// built-in JSON-LD contexts and sample VCs
const documentLoader = customLoader;

// setup quadstore
const backend = new MemoryLevel();
const df = new DataFactory();
const store = new Quadstore({ backend, dataFactory: df });
const engine = new Engine(store);
await store.open();

// store initial documents
const scope = await store.initScope();     // for preventing blank node collisions
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
  const query = req.query.query
  if (typeof query !== "string") {
    next(new Error('SPARQL query must be given as `query` parameter'));

    return;
  }
  const result = await processQuery(query, store, df, engine);
  if ('error' in result) {
    next(new Error(result.error));

    return;
  }
  res.send(result);
});

// plain SPARQL endpoint (for debug)
app.get('/sparql/', async (req, res, next) => {
  // get query string
  const query = req.query.query;
  if (typeof query !== 'string') {
    next(new Error('SPARQL query must be given as `query` parameter'));

    return;
  }

  const result = await processSparqlQuery(query, engine);
  if (typeof result === 'string') {
    next(new Error(result));

    return;
  }
  res.send(result);
});
