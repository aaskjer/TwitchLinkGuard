using System;
using System.Linq;
using System.Text;
using System.Globalization;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

public class CPHInline
{
    ///////////////////////////////////////////////////////////////////////////////
    // Configuration classes for flexible settings and message templates
    ///////////////////////////////////////////////////////////////////////////////
    
    // Settings from config.json
    public class ModerationConfig
    {
        public bool useBot { get; set; } = true;
        public string sendAction { get; set; } = "message";
        public List<string> SuspiciousKeywords { get; set; } = new List<string>();
        public List<string> SuspiciousEndings { get; set; } = new List<string>();
        public List<string> Whitelist { get; set; } = new List<string>();
        public int RequiredKeywordCount { get; set; } = 2;
        public bool SkipVipModeration { get; set; } = true; // If true, VIPs are ignored.
        public bool SkipSubModeration { get; set; } = false;
        public int TimeoutDuration { get; set; } = 600;
        public bool UseTimeout { get; set; } = false;
        public bool EnableDebugLogs { get; set; } = false;
        public bool UseTwitchWarn { get; set; } = false;
        public List<string> WhitelistedUsers { get; set; } = new List<string>();
        public bool DisableAllMessages { get; set; } = true;
    }

    // Settings from messages.json
    public class MessageConfig
    {
        public string MsgUrlDelete { get; set; } = "";
        public string MsgUrlBan { get; set; } = "";
        public string MsgObfuscated { get; set; } = "";
        public string MsgObfuscatedBan { get; set; } = "";
        public string MsgTwitchWarn { get; set; } = "";
        public string MsgTimeOut { get; set; } = "";
        public string MsgMentionTimeOut { get; set; } = "";
        public string MsgMentionBan { get; set; } = "";
    }

    private static ModerationConfig Config = null;
    private static MessageConfig Messages = null;

    ///////////////////////////////////////////////////////////////////////////////
    // Predefined regex patterns
    ///////////////////////////////////////////////////////////////////////////////
    private static readonly Regex UrlRegex = new Regex(@"((https?:\/\/)?([\w\-]+\.)+[a-zA-Z]{2,})(\/[\w\-.~:\/?#[\]@!$&'()*+,;=%]*)?",
                                                        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex TwitchBlockedPattern = new Regex(@"\*\*\*", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex VoucherCodeRegex = new Regex(@"\b[A-Z0-9]{3,6}(?:-[A-Z0-9]{3,6}){2,5}\b",
                                                              RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly UnicodeCategory[] CombiningMarkCategories = new[]
    {
        UnicodeCategory.NonSpacingMark,
        UnicodeCategory.SpacingCombiningMark,
        UnicodeCategory.EnclosingMark
    };
    private static readonly Regex MentionRegex = new Regex(@"@\w+", RegexOptions.Compiled);

    ///////////////////////////////////////////////////////////////////////////////
    // Helper methods
    ///////////////////////////////////////////////////////////////////////////////

    // Checks if a message contains a mentioned user.
    private List<string> ExtractMentionedUsers(string message)
    {
        return Regex.Matches(message, @"@(\w+)")
                    .Cast<Match>()
                    .Select(m => m.Groups[1].Value.ToLowerInvariant())
                    .Distinct()
                    .ToList();
    }

    // Removes diacritical marks from text.
    private string RemoveDiacriticalMarks(string text)
    {
        if (string.IsNullOrEmpty(text))
            return text;
        string formD = text.Normalize(NormalizationForm.FormD);
        StringBuilder sb = new StringBuilder();
        foreach (char c in formD)
        {
            UnicodeCategory uc = CharUnicodeInfo.GetUnicodeCategory(c);
            if (!CombiningMarkCategories.Contains(uc))
                sb.Append(c);
        }
        return sb.ToString().Normalize(NormalizationForm.FormC);
    }

    // Returns the list of matched keywords from the input.
    private List<string> GetMatchedKeywords(string input, List<string> keywords)
    {
        string normalizedInput = RemoveDiacriticalMarks(input);
        string inputWithoutUrls = UrlRegex.Replace(normalizedInput, "");
        var matchedKeywords = new List<string>();
        foreach (string keyword in keywords)
        {
            string normalizedKeyword = RemoveDiacriticalMarks(keyword);
            string pattern = @"(?<!\w)" + Regex.Escape(normalizedKeyword) + @"(?!\w)";
            if (Regex.Matches(inputWithoutUrls, pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled).Count > 0)
                matchedKeywords.Add(keyword);
        }
        return matchedKeywords;
    }

    // Checks if a URL is whitelisted.
    private bool IsWhitelistedUrl(string url, List<string> whitelist)
    {
        if (whitelist == null || whitelist.Count == 0)
            return false;
        foreach (string entry in whitelist)
        {
            string escapedEntry = Regex.Escape(entry).Replace("\\*", ".*");
            string pattern = "^(?:https?:\\/\\/)?(?:www\\.)?" + escapedEntry + "$";
            if (Regex.IsMatch(url, pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled))
                return true;
        }
        return false;
    }

    // Returns a suspicious ending from the input if found.
    private string GetSuspiciousEnding(string input, List<string> suspiciousEndings)
    {
        var domainMatch = Regex.Match(input, @"(?:https?:\/\/)?([\w\-]+\.[a-zA-Z]{2,})(\/[\w\-\/]*)?", RegexOptions.IgnoreCase);
        if (domainMatch.Success)
        {
            string domain = domainMatch.Groups[1].Value;
            foreach (string ending in suspiciousEndings)
            {
                string pattern = $@"{Regex.Escape(ending)}$";
                if (Regex.IsMatch(domain, pattern, RegexOptions.IgnoreCase))
                    return ending;
            }
        }
        foreach (string ending in suspiciousEndings)
        {
            string pattern = $@"\b{Regex.Escape(ending)}\b";
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return ending;
        }
        return null;
    }

    // Checks if a message appears obfuscated.
    private bool IsObfuscatedMessage(string message, List<string> suspiciousEndings)
    {
        string tldPattern = string.Join("|", suspiciousEndings).Replace(".", "");
        string obfuscationPattern = @"\b[\w\-]+(?:[\s\[\]{}()]*dot[\s\[\]{}()]*|[\s\[\]{}()]*\.[\s\[\]{}()]*)(?:" + tldPattern + @")\b";
        return Regex.IsMatch(message, obfuscationPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
    }

    private bool IsBlockedByTwitch(string message)
    {
        return TwitchBlockedPattern.IsMatch(message);
    }

    private static HashSet<string> processedMessageIds = new HashSet<string>();

    // Helper method to send messages safely.
    private void SendMessageSafe(string message, bool useBot, bool fallback)
    {
        if (!Config.DisableAllMessages && !string.IsNullOrEmpty(message))
        {
            if (Config.sendAction.Equals("action", StringComparison.OrdinalIgnoreCase))
                CPH.SendAction(message, useBot, true);
            else
                CPH.SendMessage(message, useBot, true);
        }
    }

    ///////////////////////////////////////////////////////////////////////////////
    // Init() method: Called once at startup to load and merge configurations.
    ///////////////////////////////////////////////////////////////////////////////
    public void Init()
    {
        // Use folder-based paths: if a "configFolder" argument is provided, use it; otherwise, default to a folder in MyDocuments.
        string configFolder = args.ContainsKey("configFolder") && !string.IsNullOrEmpty(args["configFolder"].ToString())
                              ? args["configFolder"].ToString(): "";
                            

        // Build full paths for the config.json and messages.json files within that folder.
        string configPath = Path.Combine(configFolder, "config.json");
        string messagesPath = Path.Combine(configFolder, "messages.json");

        // Ensure the folder exists.
        if (!Directory.Exists(configFolder))
        {
            Directory.CreateDirectory(configFolder);
            CPH.LogDebug("[TLG LOG]: Created folder: " + configFolder);
        }
        
        // Define default content for config.json.
        string defaultConfigContent = @"{
  ""_comment"": ""Configuration file for TLG. Edit with caution! Missing commas or other punctuation marks can cause the entire script to stop working!"",
  ""useBot"": true,
  ""_comment_useBot"": ""Global setting indicating whether the bot is active."",
  ""sendAction"": ""message"",
  ""_comment_sendAction"": ""Visual appearance of messages. 'action' = /me style, 'message' = normal text."",
  ""DisableAllMessages"": false,
  ""_comment_DisableAllMessages"": ""Disables all bot messages when set to true."",
  ""SkipSubModeration"": false,
  ""_comment_SkipSubModeration"": ""If set to true, subscribers (subs) are exempt from moderation."",
  ""SkipVipModeration"": true,
  ""_comment_SkipVipModeration"": ""If set to true, VIP users are skipped in moderation."",
  ""UseTwitchWarn"": false,
  ""_comment_UseTwitchWarn"": ""If set to true, only a warning is sent to Twitch for certain violations."",
  ""UseTimeout"": false,
  ""_comment_UseTimeout"": ""Specifies whether the bot issues a timeout (true) rather than a ban (false)."",
  ""TimeoutDuration"": 60,
  ""_comment_TimeoutDuration"": ""Duration (in seconds) of a timeout if that action is chosen."",
  ""RequiredKeywordCount"": 2,
  ""_comment_RequiredKeywordCount"": ""Minimum number of matching keywords required to trigger a ban/timeout."",
  ""EnableDebugLogs"": false,
  ""_commtent_EnableDebugLogs"": ""Enable if you're asked to or if you think there is something wrong."",
  ""SuspiciousKeywords"": [ ""10 Zuschauer"", ""404"", ""Aloha"", ""abo"", ""abonnement"", ""abonnieren"", ""amazing"", ""become"", ""best"",
    ""Big"", ""bits"", ""boost"", ""buy"", ""cheap"", ""cheapest"", ""cheer"", ""cheers"", ""code"", ""discount"", ""discounted"", 
    ""dogehype"", ""effortlessly boost"", ""earn"", ""fame"", ""famous"", ""follow"", ""follower"", ""followers"", ""free"",
    ""getvie"", ""gift"", ""gift card"", ""gift-card"", ""giftcard"", ""giveaway"", ""grow"", ""Gutschein"", ""Gutschein-Code"",
    ""Gutscheincode"", ""instant"", ""level"", ""money"", ""nezhna"", ""offer"", ""PayPal"", ""Prime"", ""prime"", ""Primes"",
    ""prize"", ""promo"", ""promo-code"", ""promotion"", ""promotion-code"", ""remove the space"", ""service"", ""services"",
    ""stream"", ""StreamBoo"", ""streaming"", ""streamrise"", ""sub"", ""subscriber"", ""subscribers"", ""subscription"", ""subs"",
    ""take your stream"", ""TwitchLaunch"", ""Twitch rankings"", ""twitch rankings"", ""twitchventures"", ""to/ezez"",
    ""upgrade"", ""verification"", ""view"", ""viewer"", ""viewers"", ""visit"", ""V-Bucks"", ""win"" ],
  ""_comment_SuspiciousKeywords"": ""Keywords searched in messages that trigger further checks when detected."",
  ""SuspiciousEndings"": [ ""ai"", ""be"", ""biz"", ""buzz"", ""cam"", ""cc"", ""cf"", ""click"", ""club"", ""com"", ""date"", ""de"",
    ""download"", ""ga"", ""gd"", ""gg"", ""gq"", ""icu"", ""info"", ""io"", ""loan"", ""ly"", ""men"", ""ml"", ""mov"", ""online"",
    ""page"", ""pro"", ""pw"", ""ru"", ""sc"", ""sh"", ""shop"", ""site"", ""space"", ""store"", ""su"", ""tech"", ""tk"", ""top"",
    ""trade"", ""tt"", ""tv"", ""vc"", ""website"", ""work"", ""ws"", ""xyz"", ""zip"" ],
  ""_comment_SuspiciousEndings"": ""URL endings or TLDs that are considered suspicious."",
  ""AdditionalRegexFilters"": [ ""Chẹa̬p"", ""vi̯ewers"", ""o͎n"", ""viewers̄"", ""Ĉheap ͖"", ""B͐est"" ],
  ""_comment_AdditionalRegexFilters"": ""Additional regex expressions to search in the message text to detect further suspicious content."",
  ""Whitelist"": [ ""twitch.tv/aaskjer"", ""discord.gg/FvffUkmne3"",  ""ko-fi.com/aaskjer"", ""tinyurl.com/birger-cap"",
    ""www.trachtman.de"" ],
  ""_comment_Whitelist"": ""URLs that are exempt from moderation (i.e. not further checked)."",
  ""WhitelistedUsers"": [ ""streamelements"", ""streamlabs"", ""moobot"", ""nightbot"", ""wizebot"", ""deepbot"", ""coebot"",
    ""phantombot"", ""fossabot"", ""pretzelrocks"", ""soundalerts"", ""kofistreambot"", ""sery_bot"", ""mixitup"", ""own3d"",
    ""ankhbot"", ""botisimo"", ""twitchquizbot"", ""xanbot"", ""dixper"", ""whatthedubbot"", ""tipeeebot"" ],
  ""_comment_WhitelistedUsers"": ""Exempt specific Usernames from moderation. Useful for external bots.""
}";

        // Define default content for messages.json.
        string defaultMessagesContent = @"{
  ""_comment"": ""This file contains all message templates that the bot uses for various moderation actions."",
  ""_comment_2"": ""You can use {user} to mention a user and {duration} to display the timeout duration."",
  ""MsgUrlDelete"": ""Hey @{user}, your link has been removed, please ask for permission first."",
  ""_comment_MsgUrlDelete"": ""Message displayed when a link is removed (without a ban)."",
  ""MsgUrlBan"": ""@{user} was banned for posting promotional content."",
  ""_comment_MsgUrlBan"": ""Message used when a prohibited link is detected and a ban/timeout is executed."",
  ""MsgObfuscated"": ""Hey {user}, your link looks suspicious and has been removed, please ask for permission first."",
  ""_comment_MsgObfuscated"": ""Message displayed when an obfuscated (masked) link is detected and removed."",
  ""MsgObfuscatedBan"": ""@{user} was banned for posting obfuscated promotional content."",
  ""_comment_MsgObfuscatedBan"": ""Message used when an obfuscated link is detected and a ban/timeout is executed."",
  ""MsgTwitchWarn"": ""Posting links in chat violates our Community Guidelines. This is an official warning. Continued violations may result in further action, including timeouts or suspensions."",
  ""_comment_MsgTwitchWarn"": ""Warning message sent to the user."",
  ""MsgTimeOut"": ""@{user} was timed out for {duration} seconds for rule violations."",
  ""_comment_MsgTimeOut"": ""General message displayed when a timeout is issued."",
  ""MsgMentionTimeOut"": ""@{user} made unauthorized mentions and was timed out for {duration} seconds."",
  ""_comment_MsgMentionTimeOut"": ""Message used when a timeout is issued due to unauthorized mentions.""
}";

        // --- Merge config.json ---
        JObject defaultConfig = JObject.Parse(defaultConfigContent);
        JObject userConfig;
        if (File.Exists(configPath))
        {
            string userConfigContent = File.ReadAllText(configPath);
            userConfig = JObject.Parse(userConfigContent);
        }
        else
        {
            userConfig = new JObject();
        }
        JObject mergedConfig = (JObject)defaultConfig.DeepClone();
        mergedConfig.Merge(userConfig, new JsonMergeSettings
        {
            MergeArrayHandling = MergeArrayHandling.Union,
            MergeNullValueHandling = MergeNullValueHandling.Ignore
        });
        string mergedConfigString = mergedConfig.ToString();
        if (!File.Exists(configPath) || mergedConfigString != File.ReadAllText(configPath))
        {
            File.WriteAllText(configPath, mergedConfig.ToString(Formatting.Indented));
        }
        Config = JsonConvert.DeserializeObject<ModerationConfig>(mergedConfigString);

        // --- Merge messages.json ---
        JObject defaultMessages = JObject.Parse(defaultMessagesContent);
        JObject userMessages;
        if (File.Exists(messagesPath))
        {
            string userMessagesContent = File.ReadAllText(messagesPath);
            userMessages = JObject.Parse(userMessagesContent);
        }
        else
        {
            userMessages = new JObject();
        }
        JObject mergedMessages = (JObject)defaultMessages.DeepClone();
        mergedMessages.Merge(userMessages, new JsonMergeSettings
        {
            MergeArrayHandling = MergeArrayHandling.Union,
            MergeNullValueHandling = MergeNullValueHandling.Ignore
        });
        string mergedMessagesString = mergedMessages.ToString();
        if (!File.Exists(messagesPath) || mergedMessagesString != File.ReadAllText(messagesPath))
        {
            File.WriteAllText(messagesPath, mergedMessagesString);
        }
        Messages = JsonConvert.DeserializeObject<MessageConfig>(mergedMessagesString);
    }

    // Main moderation logic
    public bool Execute()
    {
        // Ignore triggers/commands.
        if (args.ContainsKey("command") || args.ContainsKey("trigger"))
        {
            if (Config != null && Config.EnableDebugLogs)
                CPH.LogDebug("[TLG LOG]: Trigger/command detected, ignoring message.");
            return true;
        }

        // Ensure configuration is loaded.
        if (Config == null || Messages == null)
        {
            Init();
        }

        // 1) Read basic arguments.
        string input = args["message"].ToString();
        string user = args["user"].ToString();
        string msgId = args.ContainsKey("msgId") ? args["msgId"].ToString() : string.Empty;
        if (!string.IsNullOrEmpty(msgId) && processedMessageIds.Contains(msgId))
        {
            if (Config.EnableDebugLogs)
                CPH.LogDebug($"[TLG LOG]: Duplicate message skipped: {msgId}");
            return true;
        }
        processedMessageIds.Add(msgId);

        if (Config.WhitelistedUsers.Contains(user, StringComparer.OrdinalIgnoreCase))
        {
            if (Config.EnableDebugLogs)
                CPH.LogDebug($"[TLG LOG]: User '{user}' is whitelisted. Skipping moderation.");
            return true;
        }

        // Check if the user belongs to an allowed group (from Streamer.bot)
        bool userInGroup = false;
        if (args.ContainsKey("groupName") && !string.IsNullOrEmpty(args["groupName"].ToString()))
        {
            string groupName = args["groupName"].ToString();
            string[] groups = groupName.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                                       .Select(g => g.Trim()).ToArray();
            foreach (string grp in groups)
            {
                if (CPH.UserInGroup(user, Platform.Twitch, grp))
                {
                    userInGroup = true;
                    break;
                }
            }
        }
        if (userInGroup)
        {
            if (Config.EnableDebugLogs)
                CPH.LogDebug($"[TLG LOG]: User '{user}' belongs to an allowed group. Skipping moderation.");
            return true;
        }

        // 2) Role checks (permitUser, Mods, VIPs, Subs)
        string permitUser = CPH.GetGlobalVar<string>("permitUser", false);
        bool useBot = Config.useBot;
        bool isModerator = false, isVip = false, isSubscribed = false;
        CPH.TryGetArg("isSubscribed", out isSubscribed);
        CPH.TryGetArg("isVip", out isVip);
        CPH.TryGetArg("isModerator", out isModerator);

        if (isVip && Config.SkipVipModeration)
        {
            if (Config.EnableDebugLogs)
                CPH.LogDebug($"[TLG LOG]: VIP '{user}' is skipped due to SkipVipModeration = true.");
            return true;
        }
        if (!string.IsNullOrEmpty(permitUser) && user.Equals(permitUser, StringComparison.OrdinalIgnoreCase))
        {
            if (Config.EnableDebugLogs)
                CPH.LogDebug($"[TLG LOG]: '{user}' has a permit. Skipping moderation.");
            return true;
        }
        if (isModerator)
        {
            if (Config.EnableDebugLogs)
                CPH.LogDebug($"[TLG LOG]: '{user}' is a moderator. Skipping moderation.");
            return true;
        }
        if (isSubscribed && Config.SkipSubModeration)
        {
            if (Config.EnableDebugLogs)
                CPH.LogDebug($"[TLG LOG]: '{user}' is a subscriber. Skipping moderation.");
            return true;
        }

        // 3) Use configuration data from the JSON files.
        List<string> suspiciousKeywords = Config.SuspiciousKeywords;
        List<string> suspiciousEndings = Config.SuspiciousEndings;
        List<string> whitelist = Config.Whitelist;
        int requiredKeywordCount = Config.RequiredKeywordCount;

        // 4) Keyword check.
        List<string> matchedKeywords = GetMatchedKeywords(input, suspiciousKeywords);
        int matchedKeywordCount = matchedKeywords.Count;
        bool hasEnoughKeywords = (matchedKeywordCount >= requiredKeywordCount);
        if (Config.EnableDebugLogs)
            CPH.LogDebug($"[TLG LOG]: {matchedKeywordCount} suspicious keywords found: [{string.Join(", ", matchedKeywords)}]. Required: {requiredKeywordCount}.");

        // 5) Check for suspicious TLDs and obfuscated links.
        string globalEndingCheck = GetSuspiciousEnding(input, suspiciousEndings);
        bool globalObfuscated = IsObfuscatedMessage(input, suspiciousEndings);

        // 6) Message templates from messages.json.
        string msgUrlDelete = Messages.MsgUrlDelete.Replace("{user}", user);
        string msgUrlBan = Messages.MsgUrlBan.Replace("{user}", user);
        string msgObfuscated = Messages.MsgObfuscated.Replace("{user}", user);
        string msgObfuscatedBan = Messages.MsgObfuscatedBan.Replace("{user}", user);
        string msgTwitchWarn = Messages.MsgTwitchWarn.Replace("{user}", user);
        string msgTimeOut = Messages.MsgTimeOut.Replace("{user}", user).Replace("{duration}", Config.TimeoutDuration.ToString());
        string msgMentionBan = Messages.MsgMentionBan.Replace("{user}", user);

        // 7) URL check.
        var urlMatches = UrlRegex.Matches(input);
        if (urlMatches.Count > 0)
        {
            foreach (var m in urlMatches.Cast<Match>())
            {
                string url = m.Value;
                if (IsWhitelistedUrl(url, whitelist))
                {
                    CPH.LogDebug($"[TLG LOG]: URL '{url}' is whitelisted. Skipping moderation.");
                    return true;
                }
                if (hasEnoughKeywords)
                {
                    string reason = $"Possible spam detected: \"{input}\". Keywords found: [{string.Join(", ", matchedKeywords)}]. TLD: {(globalEndingCheck ?? "None")}";
                    if (Config.UseTimeout)
                    {
                        SendMessageSafe(msgTimeOut, useBot, true);
                        CPH.TwitchTimeoutUser(user, Config.TimeoutDuration, reason, useBot);
                        CPH.LogInfo($"[TLG LOG]: Timeout for '{user}' => URL + sufficient keywords. Reason: {reason}");
                    }
                    else
                    {
                        SendMessageSafe(msgUrlBan, useBot, true);
                        CPH.TwitchBanUser(user, reason, useBot);
                        CPH.LogInfo($"[TLG LOG]: Ban for '{user}' => URL + sufficient keywords. Reason: {reason}");
                    }
                    return true;
                }
                else
                {
                    if (!string.IsNullOrEmpty(globalEndingCheck))
                    {
                        SendMessageSafe(msgUrlDelete, useBot, true);
                        CPH.TwitchDeleteChatMessage(msgId, useBot);
                        CPH.LogInfo($"[TLG LOG]: Message deleted from '{user}' => URL: '{input}'");
                        if (Config.UseTwitchWarn)
                        {
                            if (!Config.DisableAllMessages)
                                CPH.TwitchWarnUser(user, msgTwitchWarn);
                            CPH.LogInfo($"[TLG LOG]: Warning for '{user}' => suspicious TLD but not enough keywords.");
                        }
                    }
                    else
                    {
                        if (Config.EnableDebugLogs)
                            CPH.LogDebug($"[TLG LOG]: URL detected, but not enough keywords. No action.");
                    }
                }
                return true;
            }
        }

        // 8) Check for mentions of non-present users with suspicious content.
        if (hasEnoughKeywords || urlMatches.Count > 0)
        {
            var mentionedUsers = Regex.Matches(input, @"@(\w+)")
                                      .Cast<Match>()
                                      .Select(m => m.Groups[1].Value.ToLowerInvariant())
                                      .ToList();
            if (mentionedUsers.Count > 0)
            {
                bool mentionedNonPresentUser = mentionedUsers.Any(mentionedUser => !mentionedUser.Equals(user, StringComparison.OrdinalIgnoreCase));
                if (mentionedNonPresentUser)
                {
                    string mentionBanReason = $"Mentioned non-present users: [{string.Join(", ", mentionedUsers)}] in message: \"{input}\" " +
                                                $"Matched keywords: [{string.Join(", ", matchedKeywords)}]. TLD: {(globalEndingCheck ?? "None")}";
                    if (Config.UseTimeout)
                    {
                        if (!Config.DisableAllMessages)
                        {
                            if (Config.sendAction.Equals("action", StringComparison.OrdinalIgnoreCase))
                                CPH.SendAction(msgTimeOut, useBot, true);
                            else
                                CPH.SendMessage(msgTimeOut, useBot, true);
                        }
                        CPH.TwitchTimeoutUser(user, Config.TimeoutDuration, mentionBanReason, useBot);
                        CPH.LogInfo($"[TLG LOG]: Timed out '{user}' for mentioning non-present users with suspicious content. Reason: {mentionBanReason}");
                    }
                    else
                    {
                        if (!Config.DisableAllMessages)
                        {
                            if (Config.sendAction.Equals("action", StringComparison.OrdinalIgnoreCase))
                                CPH.SendAction(msgMentionBan, useBot, true);
                            else
                                CPH.SendMessage(msgMentionBan, useBot, true);
                        }
                        CPH.TwitchBanUser(user, mentionBanReason, useBot);
                        CPH.LogInfo($"[TLG LOG]: Ban for '{user}' due to mentioning non-present users with suspicious content. Reason: {mentionBanReason}");
                    }
                    return true;
                }
            }
        }

        // 9) Check for obfuscated message content.
        if (IsObfuscatedMessage(input, suspiciousEndings))
        {
            if (hasEnoughKeywords)
            {
                string obfuscatedBanReason = $"Obfuscation detected: \"{input}\". Keywords found: [{string.Join(", ", matchedKeywords)}]. TLD: {(globalEndingCheck ?? "None")}";
                if (Config.UseTimeout)
                {
                    SendMessageSafe(msgTimeOut, useBot, true);
                    CPH.TwitchTimeoutUser(user, Config.TimeoutDuration, obfuscatedBanReason, useBot);
                    CPH.LogInfo($"[TLG LOG]: Timeout for '{user}' => Obfuscation + sufficient keywords. Reason: {obfuscatedBanReason}");
                }
                else
                {
                    SendMessageSafe(msgObfuscatedBan, useBot, true);
                    CPH.TwitchBanUser(user, obfuscatedBanReason, useBot);
                    CPH.LogInfo($"[TLG LOG]: Ban for '{user}' => Obfuscation + sufficient keywords. Reason: {obfuscatedBanReason}");
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(globalEndingCheck))
                {
                    SendMessageSafe(msgObfuscated, useBot, true);
                    CPH.TwitchDeleteChatMessage(msgId, true);
                    CPH.LogInfo($"[TLG LOG]: Message deleted from '{user}' => Obfuscated content: {input}.");
                }
                if (Config.UseTwitchWarn)
                {
                    CPH.TwitchWarnUser(user, msgTwitchWarn);
                    CPH.LogInfo($"[TLG LOG]: Warning for '{user}' => obfuscated link but not enough keywords.");
                }
            }
            return true;
        }

        // 10) (Optional) Additional logic (e.g., AutoMod messages) can go here.

        return true;
    }
}
