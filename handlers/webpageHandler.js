/**
 * WebpageHandler: Normalizes pre-extracted webpage text into standard input format.
 * Does NOT scrape URLs — expects text already extracted by upstream systems.
 */
class WebpageHandler {
  /**
   * Normalize webpage input into standard format
   * @param {Object} input - { type, url, text }
   * @returns {Object} - { source, content, metadata }
   */
  normalize(input) {
    if (!input || typeof input !== 'object') {
      throw new Error('WebpageHandler: input must be an object');
    }

    const url = input.url || 'unknown';
    const text = input.text || '';

    if (!text.trim()) {
      console.warn(`⚠️  WebpageHandler: Empty text received for URL "${url}"`);
    }

    return {
      source: 'webpage',
      content: text,
      metadata: {
        url,
        originalLength: text.length,
        processedAt: new Date().toISOString(),
      },
    };
  }
}

module.exports = WebpageHandler;