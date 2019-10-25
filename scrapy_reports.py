import scrapy
import json
from html2json import collect

class ReportsSpider(scrapy.Spider):
   name = "reports"
   urls = [
      'http://h1.nobbd.de/index.php?start=0'
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
      print(response.text)
      reports = json.loads(collect(response.text))
      yield {
            'reports_page_' + str(response.meta['start']) : reports['start']
      }

      if 'start' in response.meta and response.meta['start'] < int(reports['start']):
         next_page = response.meta['start']+20
         yield response.follow(response.url.replace('start=' + str(response.meta['start']), 'start=' + str(next_page)), callback=self.parse, meta={'start': next_page}, headers=self.headers)
