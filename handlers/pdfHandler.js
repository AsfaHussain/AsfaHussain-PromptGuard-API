/**
 * PDFHandler: Normalizes pre-extracted PDF text into standard input format.
 * Does NOT parse PDFs — expects text already extracted by upstream systems.
 */
class PDFHandler {
  /**
   * Normalize PDF input into standard format
   * @param {Object} input - { type, filename, text }
   * @returns {Object} - { source, content, metadata }
   */
  normalize(input) {
    if (!input || typeof input !== 'object') {
      throw new Error('PDFHandler: input must be an object');
    }

    const filename = input.filename || 'unknown.pdf';
    const text = input.text || '';

    if (!text.trim()) {
      console.warn(`⚠️  PDFHandler: Empty text received for file "${filename}"`);
    }

    return {
      source: 'pdf',
      content: text,
      metadata: {
        filename,
        originalLength: text.length,
        processedAt: new Date().toISOString(),
      },
    };
  }
}

module.exports = PDFHandler;