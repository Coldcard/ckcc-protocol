import dns.resolver
import dns.message
import dns.query

def get_dnssec_proof(handle):
    user, domain = handle.lstrip('₿').split('@')
    target = f"{user}.user._bitcoin-payment.{domain}"
    
    # 1. Setup a resolver that requests DNSSEC records (DO bit)
    resolver = dns.resolver.Resolver()
    resolver.use_edns(0, dns.flags.DO, 4096)
    
    # 2. Fetch the TXT record and its RRSIG
    answer = resolver.resolve(target, 'TXT', want_dnssec=True)
    
    # 3. Build the proof chain (This is a simplified representation)
    # In a production BIP 353 app, you'd use 'dnssec-prover' to 
    # package these into a binary RFC 9102 blob.
    proof_blobs = []
    for rrset in answer.response.answer:
        proof_blobs.append(rrset.to_wire())
        
    # Also need DS and DNSKEY records for each level of the hierarchy
    # (Root -> TLD -> Domain)
    return proof_blobs