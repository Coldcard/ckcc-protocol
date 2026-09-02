import dns.resolver
import dns.dnssec

class BIP353Resolver:
    def __init__(self, nameserver='8.8.8.8'):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [nameserver]
        self.resolver.use_edns(0, dns.flags.DO, 4096) # Request DNSSEC

    def resolve(self, handle):
        # Clean the input (e.g., ₿alice@example.com -> alice@example.com)
        handle = handle.lstrip('₿')
        user, domain = handle.split('@')
        target = f"{user}.user._bitcoin-payment.{domain}"

        try:
            # Query TXT record with DNSSEC validation
            response = self.resolver.resolve(target, 'TXT', want_dnssec=True)
            
            # Extract the URI from the TXT record
            txt_data = b"".join(response.rrset[0].strings).decode()
            
            if not txt_data.startswith("bitcoin:"):
                raise ValueError("Invalid BIP 353 record: Missing 'bitcoin:' prefix")

            return {
                'uri': txt_data,
                'validated': response.response.flags & dns.flags.AD, # Authenticated Data flag
                'rrsig': response.response.answer[1] if len(response.response.answer) > 1 else None
            }
        except Exception as e:
            return {'error': str(e)}