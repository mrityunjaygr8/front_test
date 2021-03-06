### Purpose

This repo is for testing various Vue 3 frameworks like Naive UI, Element UI, Prime Vue etc.

There are 2 routes currently:
- `"/login" route`, which takes a post json request with 2 fields called username and password, and returns a token if the login details are valid.
- `"/upload" route`, which takes a form containing 2 files, called `upload_file_1` and `upload_file_2`.  Also takes a string argument called `data`.
- `"/" route`, which returns 20 CVEs at a time, in a paginated manner.  
	Returns:
	-  "total" number of CVEs
	- "page_current" which is the current page
	- "page_total" which is the total number of pages.  
	- "data", which contains the list of the CVEs
	This route requires an Authorization header, in the following format: `Token <token>`. The token can be obtained from the login route  
	This route accepts the following optional query params:  
	- `"page"`: denoting the page to be retrieved  
	- `"severity"`: will filter the CVEs by V2Severity given  
	- `"sort_by"`: which is one of ["impactScore", "-impactScore", "exploitabilityScore", "-exploitabilityScore"], will sort by these
