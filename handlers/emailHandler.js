/**
 * EmailHandler: Normalizes pre-extracted email data into standard input format.
 * Combines sender, subject, and body into a single content string.
 */
class EmailHandler {
  /**
   * Normalize email input into standard format
   * @param {Object} input - { type, from, subject, body }
   * @returns {Object} - { source, content, metadata }
   */
  normalize(input) {
    if (!input || typeof input !== 'object') {
      throw new Error('EmailHandler: input must be an object');
    }

    const from = input.from || 'unknown@unknown.com';
    const subject = input.subject || '(no subject)';
    const body = input.body || '';

    // Combine fields into a single analyzable content string
    const content = `FROM: ${from}\nSUBJECT: ${subject}\n\n${body}`;

    if (!body.trim()) {
      console.warn(`⚠️  EmailHandler: Empty body received from "${from}"`);
    }

    return {
      source: 'email',
      content,
      metadata: {
        sender: from,
        subject,
        originalBodyLength: body.length,
        processedAt: new Date().toISOString(),
      },
    };
  }
}

module.exports = EmailHandler;