import os
import json
import requests as req


OUTDIR = os.path.join('koodous_public')
URL = 'https://api.koodous.com/public_rulesets?page=1'


def main():
    next_url = URL

    while next_url:
        print('Page {}'.format(next_url.split('=')[1]))
        r = req.get(next_url)
        json_data = r.json()

        next_url = json_data['next']

        for entry in json_data['results']:
            with open(OUTDIR + '/' + str(entry['id']) + '.yar', 'w') as outf:
                outf.write(entry['rules'])
            # with open(OUTDIR + '/complete_public' + '.yar', 'a') as outf:
            #     outf.write(entry['rules'])
            #     outf.write('\n')


if __name__ == '__main__':
    main()
