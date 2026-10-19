# Security audit report

Target: NodeGoat at `c5cb68a`

Every location quoted below was mechanically checked against the source tree by `proof-audit verify`. Findings whose citations did not match the source are listed under *Excluded* and are not reported as vulnerabilities.

## Summary

| Confirmed | Needs validation | Excluded (citation failures) | Rejected |
|---|---|---|---|
| 4 (1 critical, 1 high, 2 medium) | 0 | 0 | 0 |

## Confirmed findings

### ssjs-eval-contributions: Server-side JavaScript injection via eval() in POST /contributions

**Severity:** critical | **CWE-95**

**Attacker:** anonymous visitor who self-registers via POST /signup, then any logged-in user  
**Asset at risk:** code execution in the Node.js server process (filesystem, env, DB connection)

preTax, afterTax and roth from the request body are passed straight to eval(), so any logged-in user (and accounts are open to self-signup) can execute arbitrary JavaScript in the Node.js server process.

**Source trace**

- **entrypoint** `app/routes/index.js:52` - only isLoggedIn guards the route

  ```
  app.post("/contributions", isLoggedIn, contributionsHandler.handleContributionsUpdate);
  ```

- **evidence** `app/routes/index.js:38` - open self-registration means the login requirement is no real barrier

  ```
  app.post("/signup", sessionHandler.handleSignup);
  ```

- **control** `app/routes/session.js:36` - only checks that a session userId exists; no role or ownership check

  ```
  this.isLoggedInMiddleware = (req, res, next) => {
  if (req.session.userId) {
      return next();
  ```

- **evidence** `app/routes/session.js:235` - a fresh signup is immediately logged in

  ```
  req.session.userId = user._id;
  ```

- **sink** `app/routes/contributions.js:32`

  ```
  const preTax = eval(req.body.preTax);
  ```

- **sink** `app/routes/contributions.js:33`

  ```
  const afterTax = eval(req.body.afterTax);
  ```

- **sink** `app/routes/contributions.js:34`

  ```
  const roth = eval(req.body.roth);
  ```

- **control** `app/routes/contributions.js:47` - validation runs only after eval() has already executed the input; not an effective control

  ```
  const validations = [isNaN(preTax), isNaN(afterTax), isNaN(roth), preTax < 0, afterTax < 0, roth < 0];
  ```

- **evidence** `server.js:72` - urlencoded body (extended: false) delivers the fields as raw strings to eval; no schema validation or CSRF middleware is active (csrf block at server.js:105-114 is commented out)

  ```
  app.use(bodyParser.urlencoded({
  ```

**Fix:** Replace eval() with numeric parsing, e.g. parseInt(req.body.preTax, 10), and reject non-integers before use.

### missing-admin-authz-benefits: Missing admin authorization on GET/POST /benefits

**Severity:** high | **CWE-285**

**Attacker:** any logged-in non-admin user; accounts are open to self-registration via POST /signup, so effectively unauthenticated  
**Asset at risk:** all non-admin users' benefitStartDate (write) and their ids, first and last names (read)

The benefits routes are guarded only by isLoggedIn although an isAdmin middleware exists, so any user can list all non-admin users and change any user's benefitStartDate by supplying an arbitrary userId in the POST body.

**Source trace**

- **entrypoint** `app/routes/index.js:55`

  ```
  app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
  ```

- **entrypoint** `app/routes/index.js:56`

  ```
  app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
  ```

- **control** `app/routes/index.js:27` - admin guard exists but is not applied to these routes

  ```
  const isAdmin = sessionHandler.isAdminUserMiddleware;
  ```

- **propagation** `app/routes/benefits.js:35` - userId comes from req.body

  ```
  benefitsDAO.updateBenefits(userId, benefitStartDate, (error) => {
  ```

- **sink** `app/data/benefits-dao.js:24`

  ```
  usersCol.update({
      _id: parseInt(userId)
  }, {
  ```

- **sink** `app/data/benefits-dao.js:16`

  ```
  usersCol.find({
      "isAdmin": {
          $ne: true
      }
  })
  ```

- **control** `app/routes/session.js:36` - only checks that a session userId exists; no role or ownership check

  ```
  this.isLoggedInMiddleware = (req, res, next) => {
  if (req.session.userId) {
      return next();
  ```

- **control** `app/routes/session.js:25` - a working admin check (user.isAdmin from DB) exists but is not wired to /benefits

  ```
  this.isAdminUserMiddleware = (req, res, next) => {
  ```

- **evidence** `app/routes/benefits.js:30` - target userId and new date are taken from the request body with no ownership or role check

  ```
  const {
      userId,
      benefitStartDate
  } = req.body;
  ```

- **evidence** `app/routes/index.js:38` - open self-registration; signup handler sets req.session.userId (session.js:235)

  ```
  app.post("/signup", sessionHandler.handleSignup);
  ```

**Fix:** Add isAdmin to both routes: app.get("/benefits", isLoggedIn, isAdmin, ...) and app.post("/benefits", isLoggedIn, isAdmin, ...) (the fix is already present as a comment at app/routes/index.js:57-60).

### idor-allocations-userid: IDOR: GET /allocations/:userId returns any user's allocations

**Severity:** medium | **CWE-639**

**Attacker:** any logged-in user; accounts are open to self-registration via POST /signup, so effectively unauthenticated  
**Asset at risk:** other users' allocation percentages (stocks/funds/bonds) plus userName, firstName, lastName

The handler takes userId from the URL path instead of the session and performs no ownership check, so any logged-in user can view another user's portfolio allocations and name by changing the path parameter. Severity is medium rather than high because the exposure is read-only and limited to allocation percentages and names; user ids are small sequential integers, so enumeration is trivial.

**Source trace**

- **entrypoint** `app/routes/index.js:63`

  ```
  app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);
  ```

- **propagation** `app/routes/allocations.js:16-18` - userId taken from URL, not req.session

  ```
  const {
      userId
  } = req.params;
  ```

- **sink** `app/data/allocations-dao.js:81`

  ```
  return {
      userId: parsedUserId
  };
  ```

- **sink** `app/data/allocations-dao.js:94`

  ```
  userDAO.getUserById(alloc.userId, (err, user) => {
  ```

- **control** `app/routes/session.js:36` - only checks that a session userId exists; no role or ownership check

  ```
  this.isLoggedInMiddleware = (req, res, next) => {
  if (req.session.userId) {
      return next();
  ```

- **evidence** `app/routes/index.js:38` - open self-registration; signup handler sets req.session.userId (session.js:235)

  ```
  app.post("/signup", sessionHandler.handleSignup);
  ```

- **evidence** `app/routes/allocations.js:13` - the session-based fix is commented out

  ```
  // Fix for A4 Insecure DOR -  take user id from session instead of from URL param
  ```

- **evidence** `app/data/user-dao.js:38` - user ids are sequential integers, so other users' ids are guessable

  ```
  this.getNextSequence("userId", (err, id) => {
  ```

**Fix:** Use req.session.userId (or compare req.params.userId to it and return 403 on mismatch).

### nosqli-where-allocations-threshold: NoSQL $where injection via threshold query parameter on GET /allocations/:userId

**Severity:** medium | **CWE-943**

**Attacker:** any logged-in user; accounts are open to self-registration via POST /signup, so effectively unauthenticated  
**Asset at risk:** all users' allocation records with userName/firstName/lastName; MongoDB availability via long-running $where

The threshold query parameter is interpolated inside a quoted string in a MongoDB $where JavaScript expression, so any logged-in user (sign-up is open) can rewrite the predicate, e.g. threshold=' \|\| '1'=='1 makes it always true and returns every user's allocation percentages and names in one request, and a looping payload (0';while(true){}') ties up MongoDB JavaScript execution. Server-side JS in MongoDB cannot reach other collections, so the data exposed is the same low-sensitivity allocation data as the IDOR, plus a database availability impact.

**Source trace**

- **entrypoint** `app/routes/index.js:63`

  ```
  app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);
  ```

- **propagation** `app/routes/allocations.js:19` - threshold read from query string with no validation

  ```
  const {
      threshold
  } = req.query;
  ```

- **propagation** `app/routes/allocations.js:23` - threshold comes from req.query unvalidated

  ```
  allocationsDAO.getByUserIdAndThreshold(userId, threshold, (err, allocations) => {
  ```

- **sink** `app/data/allocations-dao.js:78`

  ```
  $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
  ```

- **propagation** `app/data/allocations-dao.js:86`

  ```
  allocationsCol.find(searchCriteria()).toArray((err, allocations) => {
  ```

- **evidence** `app/data/allocations-dao.js:70` - the parseInt/range-check fix exists only inside a comment block (lines 63-76) and is not active

  ```
  const parsedThreshold = parseInt(threshold, 10);
  ```

- **evidence** `docker-compose.yml:14` - bundled MongoDB 4.4 started without --noscripting, so $where JavaScript is enabled

  ```
  image: mongo:4.4
  ```

- **evidence** `app/routes/index.js:38` - open self-registration; signup handler sets req.session.userId (session.js:235)

  ```
  app.post("/signup", sessionHandler.handleSignup);
  ```

**Fix:** Do not build $where strings; parse threshold with parseInt, range-check it, and query with {userId: parsedUserId, stocks: {$gt: parsedThreshold}}.

## Coverage

3 planned units: 2 hunted, 1 skipped, 0 out of scope.

| Unit | Status | Findings | Checked / note |
|---|---|---|---|
| u01-http-injection | hunted | ssjs-eval-contributions, nosqli-where-allocations-threshold | contributions eval; allocations $where; login operator injection (dismissed: strict === password check); no child\_process in scope |
| u02-http-authz | hunted | idor-allocations-userid, missing-admin-authz-benefits | allocations userId; benefits admin guard; profile/signup field allowlists |
| u03-http-ssrf-redirect | skipped | - | seen in /research and /learn but not hunted in this test run |

This report lists what was found in the units examined. It is not evidence that the rest of the code is free of vulnerabilities.
