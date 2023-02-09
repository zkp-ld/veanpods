import { customLoader } from './customDocumentLoader.js';

import exampleEd25519KeyPair from './did/did_example_b34ca6cd37bbf23_test.json' assert { type: 'json' };
import exampleBls12381KeyPair from './did/exampleBls12381KeyPair.json' assert { type: 'json' };
import expExampleBls12381KeyPair from './did/exp_exampleBls12381KeyPair.json' assert { type: 'json' };
import expExampleBls12381KeyPair2 from './did/exp_exampleBls12381KeyPair2.json' assert { type: 'json' };
import expExampleBls12381KeyPair3 from './did/exp_exampleBls12381KeyPair3.json' assert { type: 'json' };
import issuerKeyPairs from './did/issuerKeyPairs.json' assert { type: 'json' };
import sampleVcs from './vc/sample_vcs.json' assert { type: 'json' };

export {
  customLoader,
  exampleBls12381KeyPair,
  exampleEd25519KeyPair,
  expExampleBls12381KeyPair,
  expExampleBls12381KeyPair2,
  expExampleBls12381KeyPair3,
  issuerKeyPairs,
  sampleVcs,
};
