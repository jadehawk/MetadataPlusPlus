#!/usr/bin/env python
# vim:fileencoding=UTF-8:ts=4:sw=4:sta:et:sts=4:ai
__license__ = 'GPL v3'

"""
Metadata++ synopsis formatting repair (v6.2.35).

Repairs FORMATTING artifacts left behind by providers' raw HTML/JSON
descriptions -- it does not rewrite, translate, or reword a single word of
the actual synopsis text. Confirmed field example (Amazon, Spanish):

    "...la cultura.&nbsp;¿Por qué está dividido..."
    "...y generosidad.McGilchrist propone..."
    "...del cerebro»TIMES LITERARY SUPPLEMENT«McGilchrist argumenta..."

Three distinct artifacts, all from HTML paragraph/line-break markup being
stripped out upstream (by the provider's own scraper or by the site itself)
without leaving a space or paragraph break behind:
  1. HTML entities (&nbsp; etc.) never decoded.
  2. A sentence-ending period directly glued to the next sentence's
     capital letter, with no space at all.
  3. Embedded press-quote blurbs (a common Amazon/publisher pattern: one
     or more "«quote» PUBLICATION NAME" blocks appended after the main
     description) glued directly onto the preceding text and each other,
     with no paragraph break and no visual separation from the
     attribution.

WHY REGEX AND NOT AN AI PROOFREADING PASS: this is a deterministic
formatting-repair problem (missing whitespace/paragraph breaks, encoded
entities), not a language-quality one -- the words themselves are already
correct, official publisher-provided copy. Routing that through an LLM
would mean sending every fetched book description to a third-party API
(cost, latency, an API-key dependency this offline-capable plugin doesn't
otherwise have, and a non-deterministic output for something that has one
correct answer). It's also unnecessary for this problem: everything below
is fully solved by decoding/normalizing/spacing repair.
"""

import re
import html

__all__ = ['clean_synopsis']

_NBSP_RE = re.compile(u'[\xa0\u2007\u202f]')
_MULTI_WS_RE = re.compile(r'[ \t]+')
_MULTI_NL_RE = re.compile(r'\n{3,}')
_BR_RE = re.compile(r'<br\s*/?>', re.I)
_TAG_RE = re.compile(r'<[^>]+>')

# A sentence-ending period/!/? immediately glued to the next sentence's
# capital letter, e.g. "...generosidad.McGilchrist propone...". Requires
# the word right before the punctuation to be >= 3 letters, so genuine
# abbreviations/initials ("U.S.", "Dr.", "J.K.") are deliberately left
# alone rather than risk splitting them apart (a real fetched sample
# containing "U.S.Grant" must NOT become "U. S. Grant").
_SENTENCE_GLUE_RE = re.compile(u'([A-Za-zÀ-ÿ]+)([.!?])(?=[A-ZÀ-Ý])')

# Only DIRECTIONAL opening quote marks (« and the curly “) — deliberately
# excludes the plain straight " character, which is used for BOTH opening
# and closing quotes in English text and so can't be told apart safely.
_QUOTE_OPEN_RE = re.compile(u'(?<=\\S)(\\s*)([«\u201c])')

# A closing quote mark directly followed by an ALL-CAPS publication/
# attribution name (the "«quote»PUBLICATION NAME" pattern), with no space
# or line break between them.
_ATTRIBUTION_RE = re.compile(
    u'([»\u201d])\\s*([A-ZÀ-Ý][A-ZÀ-Ý .\'&\\-]{2,60}?)(?=\\s*[«\u201c]|\\s*$)'
)


def _sentence_glue_repl(m):
    word, punct = m.group(1), m.group(2)
    if len(word) >= 3:
        return word + punct + ' '
    return m.group(0)


def _attribution_repl(m):
    return '{}\n\u2014 {}\n'.format(m.group(1), m.group(2).strip())


def clean_synopsis(text):
    """
    Repair HTML/whitespace formatting artifacts in a fetched synopsis.
    Idempotent (safe to call more than once / on already-clean text) and
    conservative: every rule above is scoped specifically to avoid
    mangling decimals (2.500), abbreviations (U.S., Dr.), or already
    well-formatted text using straight quotes. Returns '' unchanged for
    falsy input.
    """
    if not text:
        return text

    # 1. Decode HTML entities (&nbsp;, &amp;, &quot;, etc.)
    text = html.unescape(text)
    # 2. Convert any leftover <br> to a real newline, then strip any other
    #    leftover HTML tags a provider's scraper failed to clean up.
    text = _BR_RE.sub('\n', text)
    text = _TAG_RE.sub('', text)
    # 3. Normalize non-breaking / exotic space characters to a plain space
    #    (this is what &nbsp; decodes to in step 1: U+00A0, not a real gap).
    text = _NBSP_RE.sub(' ', text)
    # 4. Fix a sentence-ending punctuation mark glued directly onto the
    #    next sentence's capital letter.
    text = _SENTENCE_GLUE_RE.sub(_sentence_glue_repl, text)
    # 5. Give each embedded press-quote its own paragraph.
    text = _QUOTE_OPEN_RE.sub(lambda m: '\n\n' + m.group(2), text)
    # 6. Put the attribution (publication name) on its own line under the
    #    quote it belongs to, with an em dash.
    text = _ATTRIBUTION_RE.sub(_attribution_repl, text)
    # 7. Collapse any whitespace runs left over from the substitutions
    #    above, but keep the paragraph breaks we deliberately inserted.
    text = _MULTI_WS_RE.sub(' ', text)
    text = re.sub(r' *\n *', '\n', text)
    text = _MULTI_NL_RE.sub('\n\n', text)
    return text.strip()
