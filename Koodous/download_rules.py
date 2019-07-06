import requests as req
import os
import re


def save_rules(result_list):
    rules_dir = os.path.join('Rules')
    for result in result_list:
        filename = re.sub('[^a-zA-Z0-9 \n\.]', '_', result['name']) + '_' + str(result['id'])
        with open(rules_dir + '/' + filename + '.yar','w') as f:
            f.write(result['rules'])


def main():
    url = 'https://api.koodous.com/public_rulesets'

    r = req.get(url)
    response = r.json()

    while response['next']:
        save_rules(response['results'])

        r = req.get(response['next'])
        print(response['next'])
        response = r.json()


if __name__ == '__main__':
    main()