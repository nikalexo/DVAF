import scrapy
import json

class ReportsSpider(scrapy.Spider):
   name = "reports"
   urls = [
      'https://hackerone.com/hacktivity?sort_type=latest_disclosable_activity_at&filter=type:all&page=1'
   ]
   headers = {
      'x-requested-with': 'XMLHttpRequest',
      'accept': 'application/json, text/javascript, */*; q=0.01'
   }
   meta = {
      'page': 1
   }

   def start_requests(self):
      
      for url in self.urls:
         yield scrapy.Request(url=url, callback=self.parse, headers=self.headers, meta=self.meta)

   def parse(self, response):
      reports = json.loads(response.text)
      yield {
            'reports_page_' + str(response.meta['page']) : reports['reports']
      }

      if 'page' in response.meta and response.meta['page'] < int(reports['pages']):
         next_page = response.meta['page']+1
         yield response.follow(response.url.replace('page=' + str(response.meta['page']), 'page=' + str(next_page)), callback=self.parse, meta={'page': next_page}, headers=self.headers)
