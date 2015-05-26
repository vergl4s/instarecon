#!/usr/bin/env python
import dns.resolver

dns_resolver = dns.resolver.Resolver()
dns_resolver.timeout = 5
dns_resolver.lifetime = 5
