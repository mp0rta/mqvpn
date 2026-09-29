# Security policy

## Reporting a vulnerability

Do not report security problems in public issues, discussions or pull
requests. Send them privately through GitHub: on the **Security** tab of
this repository, click **Report a vulnerability**, or go directly to
<https://github.com/mp0rta/mqvpn/security/advisories/new>.

Please include as much of this as you can:

- the version or commit that has the problem, and the part affected (server,
  Linux client, Android or iOS app, or Windows client);
- how to reproduce the problem, or a proof of concept;
- what an attacker could do with it.

Please keep the problem private until we release a fix. We credit you in the
advisory unless you ask us not to.

## Supported versions

Security fixes go into the next release. Only the latest release is
supported; older releases do not get security fixes.

## Scope

This policy covers mqvpn's own code, including the forks of xquic and lwIP
bundled under `third_party/`. If you use mqvpn through OpenMPTCProuter,
which builds it from its own fork, report problems in mqvpn's code here.
Problems in OpenMPTCProuter's packaging, or in the features it adds to
mqvpn, belong to OpenMPTCProuter: report them to that project
(<https://github.com/Ysurac/openmptcprouter>).
