import { importJWK } from 'jose';

async function main() {
  try {
    const result = await importJWK({
      kty: 'OKP',
      crv: 'Ed2559',
      x: 'uqTMvIMcJSL46q3QlAtSFfL2MUnl9xla-5UEumfD6YI',
    });
    console.log(result);
  } catch (e) {
    console.log(e.message);
  }
}

main();
