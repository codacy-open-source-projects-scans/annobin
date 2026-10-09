# copyright : Copyright (c) 2017-2026 Red Hat
# license   : GNU GFDL v1.3; see accompanying LICENSE file.

What is an annobin security bug?
================================

    A security bug is one that threatens the security of a system or
    network, or might compromise the security of data stored on it.

    In the context of annobin there are two ways in which such
    bugs might occur.  In the first, the plugins or the annocheck tool
    itself might be tricked into a direct compromise of security,
    allowing operations with elevated or unauthorized permissions
    other than the executing user.  In the second, the plugins might
    be coerced into introducing a vulnerability in the compiler's
    output that was not already present in the files used as input.

    Other than that, all other bugs will be treated as non-security
    issues.  This does not mean that they will be ignored, just that
    they will not be given the priority that is given to security bugs.

    Please note, the plugins and annocheck tool are only intended to
    be used with trusted input files.  Bugs which rely upon using
    untrusted or unknown input will not be considered as security
    issues.

    In addition bugs for missed markup, either not being recorded by
    the plugins or not being reported by annocheck, are considered to
    be correctness or hardening issues and not security issues.

Reporting security bugs
=======================

    Please report (suspected) security vulnerabilities via email to
    bugzilla at:

        https://sourceware.org/bugzilla/enter_bug.cgi?product=annobin

    *Please note that all bugs reported here are public.*

    You will receive a response from us within 48 business hours. If
    the issue is confirmed, we will release a patch as soon as
    possible depending on complexity but historically within a few
    days.

    In order to report a private security bug that is not immediately
    public, please contact one of the downstream distributions with
    security teams.  The following teams have volunteered to handle
    such bugs:

      Red Hat: secalert@redhat.com
      SUSE:    security@suse.de

    Please report the bug to just one of these teams.  It will be shared
    with other teams as necessary.

    The team contacted will take care of details such as vulnerability
    rating and CVE assignment (https://cve.mitre.org/about/).  It is likely
    that the team will ask to file a public bug because the issue is
    sufficiently minor and does not warrant an embargo.  An embargo is not
    a requirement for being credited with the discovery of a security
    vulnerability.
