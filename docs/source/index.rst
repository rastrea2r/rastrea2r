.. image:: https://github.com/rastrea2r/rastrea2r/blob/master/logo.png

.. image:: https://travis-ci.org/rastrea2r/rastrea2r.svg?branch=master

.. image:: http://www.repostatus.org/badges/1.1.0/active.svg


rastrea2r
#########

Ever wanted to turn your AV console into an Incident Response & Threat Hunting machine? Rastrea2r (pronounced "rastreador" - hunter- in Spanish) is a multi-platform open source tool that allows incident responders and SOC analysts to triage suspect systems and hunt for Indicators of Compromise (IOCs) across thousands of endpoints in minutes. To parse and collect artifacts of interest from remote systems (including memory dumps), rastrea2r can execute sysinternal, system commands and other 3rd party tools across multiples endpoints, saving the output to a centralized share for automated or manual analysis. By using a client/server RESTful API, rastrea2r can also hunt for IOCs on disk and memory across multiple systems using YARA rules. As a command line tool, rastrea2r can be easily integrated within McAfee ePO, as well as other AV consoles and orchestration tools, allowing incident responders and SOC analysts to collect forensic evidence and hunt for IOCs without the need for an additional agent, with 'gusto' and style!





.. toctree::
   :maxdepth: 2
   :numbered:

   user/index
   dev/index

