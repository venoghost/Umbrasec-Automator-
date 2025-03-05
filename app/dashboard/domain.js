import { promises as dns } from 'dns';

async function resolveDomain(domain) {
  try {
    const address = await dns.lookup(domain);
    return address.address;
  } catch (err) {
    console.error('DNS lookup failed:', err);
    throw err;
  }
}

export default resolveDomain;