import random

psychology_dns = [
    'www.americanpsychologicalassociation.org',
    'www.psychologytoday.com',
    'www.associationforpsychologicalscience.org',
    'www.societyforindustrialpsychology.org',
    'www.psychology.org.au',
    'www.psychologyboard.gov.au',
    'www.academyofpsychologicalclinicalscience.org',
    'www.internationalneuropsychologicalsociety.org',
    'www.psychologicalscience.org',
    'www.psychotherapy.net',
    'www.psychologysalon.com',
    'www.psychotherapynetworker.org',
    'www.psychologytools.com',
    'www.psychologyconsultants.com.au',
    'www.lifespanpsychology.com',
    'www.psychologen-culemborg.nl',
    'www.psychologicalscience.nl',
    'www.psychologytoday.ru',
    'www.alabamapsychology.org',
    'www.psychology.wisc.edu',
    'www.psychotherapy.com',
    'www.psychologywa.org.au',
    'www.psychology-aktuell.com',
    'www.psychologyinc.com',
    'www.salfordpsychology.org',
    'www.psychologyofeating.com',
    'www.psychologycouncil.org.nz'
]

with open('dns.txt', 'w') as f:
    for i in range(0, 1000):
        dns = random.choice(psychology_dns)
        f.write(dns)
        f.write('\n')