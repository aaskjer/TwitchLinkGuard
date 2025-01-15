<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>TwitchLinkGuard - Block unwanted links</title>
  

  <h1>TwitchLinkGuard - Block unwanted links</h1>
  <p>
    <strong>TwitchLinkGuard</strong> is designed to help Twitch streamers and moderators maintain a safe and clean chat environment.
    TLG provides comprehensive tools for automated moderation, making it an essential solution for Twitch streamers looking to enhance and streamline their chat moderation.
    Its robust features and easy customization make it ideal for maintaining a safe and engaging community.
  </p>

  <h2>Key Features:</h2>
  <ul>
    <li>
      <strong>URL Detection and Filtering:</strong>
      <ul>
        <li><strong>Optimized Regex Patterns:</strong> Quickly identify URLs with precompiled regular expressions.</li>
        <li><strong>Whitelist Support:</strong> Exempt trusted domains from moderation.</li>
        <li><strong>Observed TLDs:</strong> Filter URLs with questionable top-level domains.</li>
        <li><strong>Failure Safe:</strong> URLs not explicitly flagged by the script will be ignored, ensuring users who accidentally write URL-like messages are not penalized (e.g., <code>hi.how</code>, <code>oh...my</code>).</li>
      </ul>
    </li>
    <li>
      <strong>Voucher Code Detection:</strong>
      <ul>
        <li><strong>Automatic Identification:</strong> Recognize voucher, gaming key codes, or promo codes.</li>
        <li><strong>User Sanctioning:</strong> Warn or ban users sharing unwanted code patterns.</li>
      </ul>
    </li>
    <li>
      <strong>Obfuscation Detection:</strong>
      <ul>
        <li><strong>Hidden Links:</strong> Spot intentionally obfuscated URLs (e.g., <code>example [dot] com</code>) to prevent spam and phishing.</li>
      </ul>
    </li>
    <li>
      <strong>User Group Exemptions:</strong>
      <ul>
        <li><strong>Group-Based Rules:</strong> Allow specific and optional multiple groups (e.g., <code>VIPs</code>, <code>TLG-TrustedUsers</code>) to bypass moderation.</li>
        <li><strong>Temporary Exemptions:</strong> Temporarily grant permissions to users within a specified time limit.</li>
      </ul>
    </li>
    <li>
      <strong>Keyword Filtering:</strong>
      <ul>
        <li><strong>Filter Customization:</strong> Define and monitor a set of customizable keywords and TLDs as action indicators.</li>
        <li><strong>Accurate Matching:</strong> Reduce false positives with exact matches and word boundaries.</li>
      </ul>
    </li>
    <li>
      <strong>Twitch Integration:</strong>
      <ul>
        <li><strong>Automated Actions:</strong> Delete messages, send alerts, or ban users through the Twitch API.</li>
        <li><strong>Twitch Warn System:</strong> Issue optional warnings for rule violations.</li>
      </ul>
    </li>
    <li>
      <strong>Custom Messages:</strong>
      <ul>
        <li><strong>Templates:</strong> Create personalized messages for different moderation actions.</li>
        <li><strong>Appearance:</strong> Choose the account and writing style for response messages.</li>
      </ul>
    </li>
  </ul>

  <p><em><strong>TwitchLinkGuard</strong> works with <code>stable</code> and <code>beta</code> branch of streamer.bot</em></p>

  <hr />

  <h2>Install TwitchLinkGuard</h2>

  <h3>Step 1</h3>
  <ol>
    <li>In Streamer.bot click the <strong>Import</strong> button in the top menu. Drag the <strong>.sb</strong> file into the <code>Import String</code> field.</li>
    <li>Enable the <code>TwitchLinkGuard - PermitUser</code> command in the <strong>Commands</strong> tab.</li>
  </ol>

  <h3>Step 2</h3>
  <p><strong>Editing your whitelist is important to keep your viewers safe from getting penalized by the script</strong></p>
  <ul>
    <li>Edit <code>%whitelist%</code> so users can use links from you without being punished by the script. If the argument is missing or disabled, no links will be whitelisted.</li>
    <li>Edit <code>%SuspiciousKeywords%</code> if you need other words as the default set as example in the value.</li>
    <li>Edit <code>%SuspiciousEndings%</code> if you need other TLDs (top-level-domain) as the default set as example in the value.</li>
    <li>
      <code>%isVip%</code> keeps your VIPs safe from being handled by the script.  
      If you don't trust them, or maybe just some of them, set to 'False' or disable it and use <code>%groupName%</code> instead to exempt trusted users.
    </li>
  </ul>

  <table>
    <thead>
      <tr>
        <th><strong>Argument</strong></th>
        <th><strong>Value</strong></th>
        <th><strong>Description</strong></th>
        <th><strong>Reason</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>useBot</strong></td>
        <td><strong>True</strong></td>
        <td>The bot account manages messages, bans, and timeouts.</td>
        <td>SB default setting since 0.2.5</td>
      </tr>
      <tr>
        <td><strong>useBot</strong></td>
        <td><strong>False</strong></td>
        <td>The broadcaster account manages messages, bans, and timeouts.</td>
        <td>SB default setting till 0.2.4</td>
      </tr>
      <tr>
        <td><strong>sendAction</strong></td>
        <td><strong>True</strong></td>
        <td><em>Messages appear like this in chat</em></td>
        <td>Like twitch's own <code>/me</code> command</td>
      </tr>
      <tr>
        <td><strong>sendAction</strong></td>
        <td><strong>False</strong></td>
        <td>Messages will appear as a <code>normal text</code> in chat</td>
        <td></td>
      </tr>
      <tr>
        <td><strong>useTwitchWarn</strong></td>
        <td><strong>True/False</strong></td>
        <td>If <code>True</code>, additionally issue a Twitch 'warn' for posting links</td>
        <td></td>
      </tr>
    </tbody>
  </table>

  <h3>Step 3</h3>
  <p>
    Optionally, customize the standard messages to translate them into your language or modify them to suit your preferences.
  </p>

  <hr />

  <h2>Adjust TLG-PermitUser</h2>

  <h3>Step 1</h3>
  <p><strong>Adjust TLG - Permit Options</strong></p>
  <table>
    <thead>
      <tr>
        <th><strong>Argument</strong></th>
        <th><strong>Value</strong></th>
        <th><strong>Description</strong></th>
        <th><strong>Info</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>useBot</strong></td>
        <td><strong>True</strong></td>
        <td>The bot account manages messages, bans, and timeouts.</td>
        <td>SB default setting since 0.2.5</td>
      </tr>
      <tr>
        <td><strong>useBot</strong></td>
        <td><strong>False</strong></td>
        <td>The broadcaster account manages messages, bans, and timeouts.</td>
        <td>SB default setting till 0.2.4</td>
      </tr>
      <tr>
        <td><strong>sendAction</strong></td>
        <td><strong>True</strong></td>
        <td><em>Messages appear like this in chat</em></td>
        <td>Like twitch's own <code>/me</code> command</td>
      </tr>
      <tr>
        <td><strong>sendAction</strong></td>
        <td><strong>False</strong></td>
        <td>Messages will appear as a <code>normal text</code> in chat</td>
        <td></td>
      </tr>
      <tr>
        <td><strong>permitTime</strong></td>
        <td><em>e.g. 30</em></td>
        <td>Define the time a user is allowed to post links</td>
        <td><code>permitTime</code> is always in seconds.</td>
      </tr>
    </tbody>
  </table>

  <h3>Step 2</h3>
  <p><strong>Edit the default messages optionally</strong><br />
    Add <code>{user}</code> to tag a user directly and <code>{permitTime}</code> for the specific permitted time.
  </p>
  <table>
    <thead>
      <tr>
        <th><strong>Argument</strong></th>
        <th><strong>Value</strong></th>
        <th><strong>Description</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>grantMessage</strong></td>
        <td></td>
        <td>Informs users to be granted to send links</td>
      </tr>
      <tr>
        <td><strong>revokeMessage</strong></td>
        <td></td>
        <td>Informs users when the permitted time is over</td>
      </tr>
      <tr>
        <td><strong>existingPermissionMessage</strong></td>
        <td></td>
        <td>Informs if there is already a user permitted</td>
      </tr>
      <tr>
        <td><strong>Labels</strong></td>
        <td><strong>e.g.: min, minutes, Minuten, etc.</strong></td>
        <td>Edit the desired time label after each '='</td>
      </tr>
    </tbody>
  </table>

  <hr />

  <h2>Usable Commands</h2>
  <table>
    <thead>
      <tr>
        <th><strong>Command</strong></th>
        <th><strong>Example</strong></th>
        <th><strong>Description</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>!permit</strong></td>
        <td><strong>!permit ExampleUser</strong></td>
        <td>A specific user now has 'x' seconds to post a link</td>
      </tr>
    </tbody>
  </table>

  <hr />

  <h2>Contributors</h2>
  <p>
    <a href="https://extensions.streamer.bot/u/ybo/activity">aaskjer</a>
  </p>
  <p class="icon-links">
    <!-- Update these image URLs to your actual assets if available -->
    <a href="https://www.twitch.tv/aaskjer">
      <img src="upload://sM6sDP2FtFeSXmO2Fyb4eq4HNdG.png" alt="Twitch">
    </a>
    <a href="https://discord.com/channels/834650675224248362/1321581223746863207">
      <img src="upload://mi4Bb9SNcd3ozvii9RBuHB5okMC.png" alt="Discord">
    </a>
  </p>

</body>
</html>
