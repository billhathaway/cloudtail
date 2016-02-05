cloudtail
--

NOTICE: super early, very little works right now
--

Cloudtail reads a stream of AWS [CloudTrail](https://aws.amazon.com/cloudtrail/CloudTrail) events and can send them to services such as Slack or Hipchat.
You can also temporarily or permanently silence events matching filters to reduce the noise level.

Planned: ability to modify templates changing what data is output per event.

API endpoint|Methods|Comments
---|---|---
/status|GET|health  
/admin|GET|server settings  
/stash|GET/POST/DELETE|manage filters  
/test|POST|send mock CloudTrail events to test
