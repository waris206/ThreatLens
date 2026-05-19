function topSignal(signals = []) {
  if (!Array.isArray(signals) || signals.length === 0) return 'No signal recorded';
  const sorted = [...signals].sort((a, b) => Math.abs(b.delta || 0) - Math.abs(a.delta || 0));
  return sorted[0]?.signal || sorted[0]?.factor || 'No signal recorded';
}

async function postWebhook(url, payload) {
  if (!url) return;
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (error) {
    console.warn('Webhook alert skipped:', error.message);
  }
}

/**
 * Send optional Slack/Discord alerts for high-risk detections.
 *
 * Missing webhook environment variables are intentionally silent: alerting is
 * an integration layer and must never break the deterministic analysis path.
 *
 * @param {{
 *   filename: string,
 *   score: number,
 *   classification: string,
 *   signals: Array,
 *   analysisId: string
 * }} alert
 */
export async function sendHighRiskAlert(alert) {
  if (!alert || alert.score <= 80) return;

  const signal = topSignal(alert.signals);
  const slackUrl = process.env.SLACK_WEBHOOK_URL;
  const discordUrl = process.env.DISCORD_WEBHOOK_URL;

  await Promise.all([
    postWebhook(slackUrl, {
      text: 'ThreatLens HIGH RISK Detection',
      attachments: [{
        color: 'danger',
        fields: [
          { title: 'File', value: alert.filename || 'Unknown' },
          { title: 'Risk Score', value: `${alert.score}/100` },
          { title: 'Classification', value: alert.classification || 'UNKNOWN' },
          { title: 'Top Signal', value: signal },
          { title: 'Analysis ID', value: alert.analysisId },
        ],
      }],
    }),
    postWebhook(discordUrl, {
      content: 'ThreatLens HIGH RISK Detection',
      embeds: [{
        title: 'ThreatLens HIGH RISK Detection',
        color: 0xff0033,
        fields: [
          { name: 'File', value: alert.filename || 'Unknown', inline: true },
          { name: 'Risk Score', value: `${alert.score}/100`, inline: true },
          { name: 'Classification', value: alert.classification || 'UNKNOWN', inline: true },
          { name: 'Top Signal', value: signal, inline: false },
          { name: 'Analysis ID', value: alert.analysisId, inline: false },
        ],
      }],
    }),
  ]);
}
