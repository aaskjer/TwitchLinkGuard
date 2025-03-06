using System;
using System.Linq;
using System.Text;
using System.Globalization;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net;
using Newtonsoft.Json.Linq;

public class CPHInline
{
    private bool IsValidTwitchUsername(string username)
    {
        if (string.IsNullOrEmpty(username))
            return false;
        string pattern = @"^[a-zA-Z0-9_]{4,25}$";
        return Regex.IsMatch(username, pattern);
    }

    ///////////////////////////////////////////////////////////////////////////////
    // Precompiled Regex patterns
    ///////////////////////////////////////////////////////////////////////////////
    private static readonly Regex UrlRegex = new Regex(@"((https?:\/\/)?([\w\-]+\.)+[a-zA-Z]{2,})(\/[\w\-.~:\/?#[\]@!$&'()*+,;=%]*)?", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex TwitchBlockedPattern = new Regex(@"\*\*\*", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex VoucherCodeRegex = new Regex(@"\b[A-Z0-9]{3,6}(?:-[A-Z0-9]{3,6}){2,5}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly UnicodeCategory[] CombiningMarkCategories = new[]
    {
        UnicodeCategory.NonSpacingMark,
        UnicodeCategory.SpacingCombiningMark,
        UnicodeCategory.EnclosingMark
    };
    // Precompiled Regex pattern to detect user mentions
    private static readonly Regex MentionRegex = new Regex(@"@\w+", RegexOptions.Compiled);
    // Method to extract mentioned users from a message
    private List<string> ExtractMentionedUsers(string message)
    {
        var matches = MentionRegex.Matches(message).Cast<Match>().Select(m => m.Value.TrimStart('@').ToLower()).Distinct().ToList();
        return matches;
    }

    ///////////////////////////////////////////////////////////////////////////////
    // Removes combining/diacritical marks
    ///////////////////////////////////////////////////////////////////////////////
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

    ///////////////////////////////////////////////////////////////////////////////
    // Returns a list of which suspicious keywords were matched in the input
    ///////////////////////////////////////////////////////////////////////////////
    private List<string> GetMatchedKeywords(string input, List<string> keywords)
    {
        string normalizedInput = RemoveDiacriticalMarks(input);
        string inputWithoutUrls = UrlRegex.Replace(normalizedInput, "");
        var matchedKeywords = new List<string>();
        foreach (string keyword in keywords)
        {
            string normalizedKeyword = RemoveDiacriticalMarks(keyword);
            string pattern = @"(?<!\w)" + Regex.Escape(normalizedKeyword) + @"(?!\w)";
            MatchCollection matches = Regex.Matches(inputWithoutUrls, pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
            if (matches.Count > 0)
                matchedKeywords.Add(keyword);
        }

        return matchedKeywords;
    }

    ///////////////////////////////////////////////////////////////////////////////
    // Checks against a list of defined whitelisted URLs
    ///////////////////////////////////////////////////////////////////////////////
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

    ///////////////////////////////////////////////////////////////////////////////
    // Checks against a list of defined blocked endings (TLDs)
    ///////////////////////////////////////////////////////////////////////////////
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

    ///////////////////////////////////////////////////////////////////////////////
    // Checks messages for obfuscation patterns
    ///////////////////////////////////////////////////////////////////////////////
    private bool IsObfuscatedMessage(string message, List<string> suspiciousEndings)
    {
        string tldPattern = string.Join("|", suspiciousEndings).Replace(".", "");
        string obfuscationPattern = @"\b[\w\-]+(?:[\s\[\]{}()]*dot[\s\[\]{}()]*|[\s\[\]{}()]*\.[\s\[\]{}()]*)(?:" + tldPattern + @")\b";
        MatchCollection voucherMatches = VoucherCodeRegex.Matches(message);
        if (voucherMatches.Count > 0)
        {
            foreach (Match voucherMatch in voucherMatches)
            {
                string voucherCode = voucherMatch.Value;
                CPH.LogInfo($"TLG LOG: Detected voucher code: '{voucherCode}'");
                return true;
            }
        }

        return Regex.IsMatch(message, obfuscationPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
    }

    ///////////////////////////////////////////////////////////////////////////////
    // Helper method: Get Twitch user info via HTTP from the Twitch Helix API.
    // Requires global variables "TwitchClientID" and "TwitchOAuthToken" to be set.
    ///////////////////////////////////////////////////////////////////////////////
    private string GetTwitchUserInfo(string username)
    {
        string url = $"https://api.twitch.tv/helix/users?login={username}";
        string clientId = CPH.GetGlobalVar<string>("TwitchClientID", false);
        string oauthToken = CPH.GetGlobalVar<string>("TwitchOAuthToken", false);
        var headers = new Dictionary<string, string>()
        {
            {
                "Client-ID",
                clientId
            },
            {
                "Authorization",
                $"Bearer {oauthToken}"}
        };
        try
        {
            using (var wc = new WebClient())
            {
                foreach (var kv in headers)
                {
                    wc.Headers.Add(kv.Key, kv.Value);
                }

                return wc.DownloadString(url);
            }
        }
        catch (Exception ex)
        {
            CPH.LogError($"TLG LOG: Error fetching Twitch user info: {ex.Message}");
            return null;
        }
    }

    ///////////////////////////////////////////////////////////////////////////////
    // Checks if a message contains '***' (blocked URL by Twitch)
    ///////////////////////////////////////////////////////////////////////////////
    private bool IsBlockedByTwitch(string message)
    {
        return TwitchBlockedPattern.IsMatch(message);
    }

    // Single static definition for processed message IDs.
    private static HashSet<string> processedMessageIds = new HashSet<string>();
    ///////////////////////////////////////////////////////////////////////////////
    public bool Execute()
    {
        //----------------------------------------------------------------
        // 1) Retrieve basic arguments
        //----------------------------------------------------------------
        string input = args["message"].ToString();
        string user = args["user"].ToString();
        string messageId = args.ContainsKey("msgId") ? args["msgId"].ToString() : string.Empty;
        // Prevent duplicate processing of the same message
        if (!string.IsNullOrEmpty(messageId) && processedMessageIds.Contains(messageId))
        {
            CPH.LogDebug($"TLG LOG: Skipping duplicate event for message ID: {messageId}");
            return true; // Skip further processing
        }

        processedMessageIds.Add(messageId);
        // Validate Twitch username before proceeding
        if (!IsValidTwitchUsername(user))
        {
            CPH.LogError($"TLG LOG: Invalid username detected: '{user}'. Skipping action.");
            return true; // Prevent further processing
        }

        //----------------------------------------------------------------
        // 2) Handle any required actions (e.g., Twitch API, if applicable)
        //----------------------------------------------------------------
        try
        {
            CPH.LogDebug($"TLG LOG: Successfully validated and prepared user '{user}'.");
        }
        catch (Exception ex)
        {
            CPH.LogError($"TLG LOG: Unexpected error while processing user '{user}': {ex.Message}");
            return true; // Safely stop further processing
        }

        // Possibly retrieve a permit user if using that system
        string permitUser = CPH.GetGlobalVar<string>("permitUser", false);
        bool sendAction = false;
        CPH.TryGetArg("sendAction", out sendAction);
        bool fallback = args.ContainsKey("fallback") ? bool.Parse(args["fallback"].ToString()) : true;
        bool useBot = false;
        CPH.TryGetArg("useBot", out useBot);
        // Roles
        bool isModerator = false, isVip = false, isSubscribed = false;
        CPH.TryGetArg("isSubscribed", out isSubscribed);
        CPH.TryGetArg("isVip", out isVip);
        CPH.TryGetArg("isModerator", out isModerator);
        // Whether to skip moderation for VIP or Sub
        bool skipVipModeration = args.ContainsKey("skipVipModeration") ? Convert.ToBoolean(args["skipVipModeration"]) : true;
        bool skipSubModeration = args.ContainsKey("skipSubModeration") ? Convert.ToBoolean(args["skipSubModeration"]) : false;
        // Additional roles checks
        CPH.TryGetArg("groupName", out string groupName);
        CPH.TryGetArg("userName", out string userName);
        // If `useTimeout = true`, we do timeouts. If false, we do bans.
        bool useTimeout = args.ContainsKey("useTimeout") ? Convert.ToBoolean(args["useTimeout"]) : false;
        // For timeouts
        int duration = args.ContainsKey("duration") ? Convert.ToInt32(args["duration"]) : 600;
        //----------------------------------------------------------------
        // 2) requiredKeywordCount
        //----------------------------------------------------------------
        int requiredKeywordCount = args.ContainsKey("requiredKeywordCount") ? Convert.ToInt32(args["requiredKeywordCount"]) : 2;
        //----------------------------------------------------------------
        // 3) Check trusted groups, bot user, mod, etc.
        //----------------------------------------------------------------
        bool userInGroup = false;
        if (!string.IsNullOrEmpty(groupName))
        {
            string[] groups = groupName.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(g => g.Trim()).ToArray();
            foreach (string grp in groups)
            {
                if (CPH.UserInGroup(userName, Platform.Twitch, grp))
                {
                    userInGroup = true;
                    break;
                }
            }
        }

        if (userInGroup)
        {
            CPH.LogDebug($"TLG LOG: '{userName}' is in an exempt group => skip moderation.");
            return true;
        }

        var botInfo = CPH.TwitchGetBot();
        string botName = botInfo?.UserName ?? "";
        if (!string.IsNullOrEmpty(botName) && user.Equals(botName, StringComparison.OrdinalIgnoreCase))
        {
            CPH.LogDebug($"TLG LOG: '{user}' is the Streamer.bot bot => skip moderation.");
            return true;
        }

        if (isModerator)
        {
            CPH.LogDebug($"TLG LOG: '{user}' is a Moderator => skip moderation.");
            return true;
        }

        if (!string.IsNullOrEmpty(permitUser) && user.Equals(permitUser, StringComparison.OrdinalIgnoreCase))
        {
            CPH.LogDebug($"TLG LOG: '{user}' has a permit => skip moderation.");
            return true;
        }

        if (isVip && skipVipModeration)
        {
            CPH.LogDebug($"TLG LOG: '{user}' is VIP + skipVipModeration => skip.");
            return true;
        }

        if (isSubscribed && skipSubModeration)
        {
            CPH.LogDebug($"TLG LOG: '{user}' is Subscribed + skipSubModeration => skip.");
            return true;
        }

        //----------------------------------------------------------------
        // 4) Parse suspiciousKeywords, suspiciousEndings, whitelist
        //----------------------------------------------------------------
        List<string> suspiciousKeywords = new List<string>();
        List<string> suspiciousEndings = new List<string>();
        List<string> whitelist = new List<string>();
        if (args.ContainsKey("suspiciousKeywords"))
        {
            try
            {
                var parts = args["suspiciousKeywords"].ToString().Split(',');
                foreach (string part in parts)
                {
                    string trimmed = part.Trim();
                    if (!string.IsNullOrEmpty(trimmed))
                        suspiciousKeywords.Add(trimmed);
                }
            }
            catch
            {
                CPH.LogWarn("TLG LOG: Failed to parse 'suspiciousKeywords'. It remains empty.");
            }
        }

        if (args.ContainsKey("suspiciousEndings"))
        {
            try
            {
                var parts = args["suspiciousEndings"].ToString().Split(',');
                foreach (string part in parts)
                {
                    string trimmed = part.Trim();
                    if (!string.IsNullOrEmpty(trimmed))
                        suspiciousEndings.Add(trimmed);
                }
            }
            catch
            {
                CPH.LogWarn("TLG LOG: Failed to parse 'suspiciousEndings'. It remains empty.");
            }
        }

        if (args.ContainsKey("whitelist"))
        {
            try
            {
                var parts = args["whitelist"].ToString().Split(',');
                foreach (string part in parts)
                {
                    string trimmed = part.Trim();
                    if (!string.IsNullOrEmpty(trimmed))
                        whitelist.Add(trimmed);
                }
            }
            catch
            {
                CPH.LogWarn("TLG LOG: Failed to parse 'whitelist'. It remains empty.");
            }
        }

        bool useTwitchWarnFlag = args.ContainsKey("useTwitchWarn") && bool.TryParse(args["useTwitchWarn"]?.ToString(), out var globalWarnFlag) && globalWarnFlag;
        //----------------------------------------------------------------
        // 5) Count suspicious keywords
        //----------------------------------------------------------------
        List<string> matchedKeywords = GetMatchedKeywords(input, suspiciousKeywords);
        int matchedKeywordCount = matchedKeywords.Count;
        bool hasEnoughKeywords = (matchedKeywordCount >= requiredKeywordCount);
        CPH.LogDebug($"TLG LOG: Found {matchedKeywordCount} suspicious keyword(s): " + $"[{string.Join(", ", matchedKeywords)}]. " + $"Required for ban/timeout={requiredKeywordCount}. Enough? {hasEnoughKeywords}");
        //----------------------------------------------------------------
        // 6) Check suspicious TLD + obfuscation
        //----------------------------------------------------------------
        string globalEndingCheck = GetSuspiciousEnding(input, suspiciousEndings);
        bool globalObfuscated = IsObfuscatedMessage(input, suspiciousEndings);
        //----------------------------------------------------------------
        // 7) Additional messages: prepare message templates
        //----------------------------------------------------------------
        bool disableAllMessages = args.ContainsKey("disableAllMessages") && Convert.ToBoolean(args["disableAllMessages"]);
        string msgVoucherBanTemplate = args.ContainsKey("msgVoucherBan") ? args["msgVoucherBan"].ToString() : "";
        string msgVoucherBan = msgVoucherBanTemplate.Replace("{user}", user);
        string msgUrlDeleteTemplate = args.ContainsKey("msgUrlDelete") ? args["msgUrlDelete"].ToString() : "";
        string msgUrlDelete = msgUrlDeleteTemplate.Replace("{user}", user);
        string msgUrlBanTemplate = args.ContainsKey("msgUrlBan") ? args["msgUrlBan"].ToString() : "";
        string msgUrlBan = msgUrlBanTemplate.Replace("{user}", user);
        string msgObfuscatedTemplate = args.ContainsKey("msgObfuscated") ? args["msgObfuscated"].ToString() : "";
        string msgObfuscated = msgObfuscatedTemplate.Replace("{user}", user);
        string msgObfuscatedBanTemplate = args.ContainsKey("msgObfuscatedBan") ? args["msgObfuscatedBan"].ToString() : "";
        string msgObfuscatedBan = msgObfuscatedBanTemplate.Replace("{user}", user);
        string msgIsBlockedTemplate = args.ContainsKey("msgIsBlocked") ? args["msgIsBlocked"].ToString() : "";
        string msgIsBlocked = msgIsBlockedTemplate.Replace("{user}", user);
        string msgIsBlockedBanTemplate = args.ContainsKey("msgIsBlockedBan") ? args["msgIsBlockedBan"].ToString() : "";
        string msgIsBlockedBan = msgIsBlockedBanTemplate.Replace("{user}", user);
        string msgAutoDenyBanTemplate = args.ContainsKey("msgAutoDenyBan") ? args["msgAutoDenyBan"].ToString() : "";
        string msgAutoDenyBan = msgAutoDenyBanTemplate.Replace("{user}", user);
        string msgTwitchWarnTemplate = args.ContainsKey("msgTwitchWarn") ? args["msgTwitchWarn"].ToString() : "";
        string msgTwitchWarn = msgTwitchWarnTemplate.Replace("{user}", user);
        string msgTimeOutTemplate = args.ContainsKey("msgTimeOut") ? args["msgTimeOut"].ToString() : "";
        string msgTimeOut = msgTimeOutTemplate.Replace("{user}", user).Replace("{duration}", duration.ToString());
        string msgMentionTimeOutTemplate = args.ContainsKey("msgMentionTimeOut") ? args["msgMentionTimeOut"].ToString() : "";
        string msgMentionTimeOut = msgMentionTimeOutTemplate.Replace("{user}", user).Replace("{duration}", duration.ToString());
        string msgMentionBanTemplate = args.ContainsKey("msgMentionBan") ? args["msgMentionBan"].ToString() : "";
        string msgMentionBan = msgMentionBanTemplate.Replace("{user}", user);
        string msgAccountBanTemplate = args.ContainsKey("msgAccountBan") ? args["msgAccountBan"].ToString() : "";
        string msgAccountBan = msgAccountBanTemplate.Replace("{user}", user);

		//----------------------------------------------------------------
		// NEW SYSTEM: Block messages from new accounts containing suspicious keywords or suspicious endings
		//----------------------------------------------------------------
		if (args.ContainsKey("accountAgeThreshold") && (matchedKeywords.Count > 0 || !string.IsNullOrEmpty(globalEndingCheck)))
		{
			int accountAgeThreshold = Convert.ToInt32(args["accountAgeThreshold"]);
			string accountAgeUnit = args.ContainsKey("accountAgeUnit") ? args["accountAgeUnit"].ToString().ToLower() : "hours";
			TimeSpan threshold;
			switch (accountAgeUnit)
			{
				case "days":
					threshold = TimeSpan.FromDays(accountAgeThreshold);
					break;
				case "months":
					threshold = TimeSpan.FromDays(accountAgeThreshold * 30);
					break;
				case "hours":
				default:
					threshold = TimeSpan.FromHours(accountAgeThreshold);
					break;
			}
			string userInfoJson = GetTwitchUserInfo(user);
			if (!string.IsNullOrEmpty(userInfoJson))
			{
				try
				{
					// Use JObject to avoid dynamic binder issues.
					JObject userInfo = JObject.Parse(userInfoJson);
					if (userInfo != null && userInfo["data"] != null && userInfo["data"].HasValues)
					{
						JToken firstUser = userInfo["data"].First;
						if (firstUser["created_at"] != null)
						{
							DateTime creationDate;
							if (DateTime.TryParse(firstUser["created_at"].ToString(), out creationDate))
							{
								creationDate = creationDate.ToUniversalTime();
								TimeSpan accountAge = DateTime.UtcNow - creationDate;
								string ageDenyReason = $"Account too new for posting suspicious content." + $"Matched: [{string.Join(", ", matchedKeywords)}]. " + $"TLD: {(globalEndingCheck ?? "None")}";
								if (accountAge < threshold)
								{
									CPH.LogInfo($"TLG LOG: Blocking message from '{user}' because account age {accountAge} is less than threshold {threshold}.");
									CPH.TwitchDeleteChatMessage(messageId, useBot);
									if (!disableAllMessages)
									{
										if (useTimeout)
										{
											if (sendAction)
												CPH.SendAction(msgTimeOut, useBot, fallback);
											else
												CPH.SendMessage(msgTimeOut, useBot, fallback);
											CPH.TwitchTimeoutUser(user, duration, ageDenyReason, useBot);
											CPH.LogInfo($"TLG LOG: Timed out new account '{user}' due to insufficient account age.");
										}
										else
										{
											if (sendAction)
												CPH.SendAction(msgAccountBan, useBot, fallback);
											else
												CPH.SendMessage(msgAccountBan, useBot, fallback);
											CPH.TwitchBanUser(user, ageDenyReason, useBot);
											CPH.LogInfo($"TLG LOG: Banned new account '{user}' due to insufficient account age.");
										}
									}
									return true;
								}
							}
						}
					}
				}
				catch (Exception ex)
				{
					CPH.LogError($"TLG LOG: Error parsing Twitch user info for '{user}': {ex.Message}");
				}
			}
		}
        
        //----------------------------------------------------------------
        // 8) Check for voucher codes => punish only if hasEnoughKeywords
        //----------------------------------------------------------------
        MatchCollection voucherMatches = VoucherCodeRegex.Matches(input);
        if (voucherMatches.Count > 0)
        {
            foreach (Match match in voucherMatches)
            {
                string voucherCode = match.Value;
                CPH.LogInfo($"TLG LOG: Detected voucher code: '{voucherCode}'");
                if (hasEnoughKeywords)
                {
                    string voucherReason = $"Voucher-Code detected. Message: \"{input}\" " + $"Matched: [{string.Join(", ", matchedKeywords)}]. " + $"TLD: {(globalEndingCheck ?? "None")}";
                    if (useTimeout)
                    {
                        if (!disableAllMessages)
                        {
                            if (sendAction)
                                CPH.SendAction(msgTimeOut, useBot, fallback);
                            else
                                CPH.SendMessage(msgTimeOut, useBot, fallback);
                        }

                        CPH.TwitchTimeoutUser(user, duration, voucherReason, useBot);
                        CPH.LogInfo($"TLG LOG: Timed out '{user}' => voucher + enough keywords. Reason: {voucherReason}");
                    }
                    else
                    {
                        if (!disableAllMessages)
                        {
                            if (sendAction)
                                CPH.SendAction(msgVoucherBan, useBot, fallback);
                            else
                                CPH.SendMessage(msgVoucherBan, useBot, fallback);
                        }

                        CPH.TwitchBanUser(user, voucherReason, useBot);
                        CPH.LogInfo($"TLG LOG: Banned '{user}' => voucher + enough keywords. Reason: {voucherReason}");
                    }
                }
                else
                {
                    if (useTwitchWarnFlag)
                    {
                        if (!disableAllMessages)
                            CPH.TwitchWarnUser(user, msgTwitchWarn);
                        CPH.LogInfo($"TLG LOG: Warned '{user}' => voucher code, but not enough keywords");
                    }
                }

                return true;
            }
        }

        //----------------------------------------------------------------
        // 9) Twitch-blocked (***)
        //----------------------------------------------------------------
		if (IsBlockedByTwitch(input)) // Pass both parameters
		{
			if (hasEnoughKeywords)
			{
				string blockedBanReason = $"Flagged as potential advertising spam message: \"{input}\" " +
										  $"Matched: [{string.Join(", ", matchedKeywords)}]. " +
										  $"TLD: {(globalEndingCheck ?? "None")}";

				if (useTimeout)
				{
					if (!disableAllMessages)
					{
						if (sendAction)
							CPH.SendAction(msgTimeOut, useBot, fallback);
						else
							CPH.SendMessage(msgTimeOut, useBot, fallback);
					}

					CPH.TwitchTimeoutUser(user, duration, blockedBanReason, useBot);
					CPH.LogInfo($"TLG LOG: Timed out '{user}' => *** + enough keywords. Reason: {blockedBanReason}");
				}
				else
				{
					if (!disableAllMessages)
					{
						if (sendAction)
							CPH.SendAction(msgUrlBan, useBot, fallback);
						else
							CPH.SendMessage(msgUrlBan, useBot, fallback);
					}

					CPH.TwitchBanUser(user, blockedBanReason, useBot);
					CPH.LogInfo($"TLG LOG: Banned '{user}' => *** + enough keywords. Reason: {blockedBanReason}");
				}

				// Only delete the message if it meets the keyword threshold
				CPH.TwitchDeleteChatMessage(messageId, useBot);
				return true;
			}
			else
			{
				if (useTwitchWarnFlag)
				{
					if (!disableAllMessages)
						CPH.TwitchWarnUser(user, msgTwitchWarn);
					CPH.LogInfo($"TLG LOG: Warned '{user}' => *** but not enough keywords.");
				}
			}

			return true;
		}

        //----------------------------------------------------------------
        // 10) Check for actual URLs
        //----------------------------------------------------------------
        MatchCollection urlMatches = UrlRegex.Matches(input);
        if (urlMatches.Count > 0)
        {
            foreach (Match m in urlMatches)
            {
                string url = m.Value;
                if (IsWhitelistedUrl(url, whitelist))
                {
                    CPH.LogInfo($"TLG LOG: URL '{url}' is whitelisted => skip moderation.");
                    return true;
                }

                if (hasEnoughKeywords)
                {
                    string reason = $"Flagged as potential advertising spam message: \"{input}\" " + $"Matched: [{string.Join(", ", matchedKeywords)}]. " + $"TLD: {(globalEndingCheck ?? "None")}";
                    if (useTimeout)
                    {
                        if (!disableAllMessages)
                        {
                            if (sendAction)
                                CPH.SendAction(msgTimeOut, useBot, fallback);
                            else
                                CPH.SendMessage(msgTimeOut, useBot, fallback);
                        }

                        CPH.TwitchTimeoutUser(user, duration, reason, useBot);
                        CPH.LogInfo($"TLG LOG: Timed out '{user}' => URL + enough keywords. Reason: {reason}");
                    }
                    else
                    {
                        if (!disableAllMessages)
                        {
                            if (sendAction)
                                CPH.SendAction(msgUrlBan, useBot, fallback);
                            else
                                CPH.SendMessage(msgUrlBan, useBot, fallback);
                        }

                        CPH.TwitchBanUser(user, reason, useBot);
                        CPH.LogInfo($"TLG LOG: Banned '{user}' => URL + enough keywords. Reason: {reason}");
                    }

                    return true;
                }
                else
                {
                    if (!string.IsNullOrEmpty(globalEndingCheck))
                    {
                        if (!disableAllMessages)
                        {
                            if (sendAction)
                                CPH.SendAction(msgUrlDelete, useBot, fallback);
                            else
                                CPH.SendMessage(msgUrlDelete, useBot, fallback);
                        }

                        CPH.TwitchDeleteChatMessage(messageId, useBot);
                        if (useTwitchWarnFlag)
                        {
                            if (!disableAllMessages)
                                CPH.TwitchWarnUser(user, msgTwitchWarn);
                            CPH.LogInfo($"TLG LOG: Warned '{user}' => suspicious TLD but not enough keywords.");
                        }
                    }
                    else
                    {
                        CPH.LogInfo($"TLG LOG: URL found but not enough keywords => skip/ignore");
                    }
                }

                return true;
            }
        }

        //----------------------------------------------------------------
        // 11) Check for mentions of non-present users with suspicious content
        //----------------------------------------------------------------
        if (hasEnoughKeywords || urlMatches.Count > 0)
        {
            var mentionedUsers = Regex.Matches(input, @"@(\w+)").Cast<Match>().Select(m => m.Groups[1].Value.ToLowerInvariant()).ToList();
            if (mentionedUsers.Count > 0)
            {
                bool mentionedNonPresentUser = mentionedUsers.Any(mentionedUser => !mentionedUser.Equals(user, StringComparison.OrdinalIgnoreCase));
                if (mentionedNonPresentUser)
                {
                    string mentionBanReason = $"Mentioned non-present users: [{string.Join(", ", mentionedUsers)}] in message: \"{input}\" " + $"Matched keywords: [{string.Join(", ", matchedKeywords)}]. " + $"TLD: {(globalEndingCheck ?? "None")}";
                    if (useTimeout)
                    {
                        if (!disableAllMessages)
                        {
                            if (sendAction)
                                CPH.SendAction(msgMentionTimeOut, useBot, fallback);
                            else
                                CPH.SendMessage(msgMentionTimeOut, useBot, fallback);
                        }

                        CPH.TwitchTimeoutUser(user, duration, mentionBanReason, useBot);
                        CPH.LogInfo($"TLG LOG: Timed out '{user}' for mentioning non-present users with suspicious content. Reason: {mentionBanReason}");
                    }
                    else
                    {
                        if (!disableAllMessages)
                        {
                            if (sendAction)
                                CPH.SendAction(msgMentionBan, useBot, fallback);
                            else
                                CPH.SendMessage(msgMentionBan, useBot, fallback);
                        }

                        CPH.TwitchBanUser(user, mentionBanReason, useBot);
                        CPH.LogInfo($"TLG LOG: Banned '{user}' for mentioning non-present users with suspicious content. Reason: {mentionBanReason}");
                    }

                    return true;
                }
            }
        }

        //----------------------------------------------------------------
        // 12) Check obfuscated => ban/timeout only if hasEnoughKeywords
        //----------------------------------------------------------------
        if (globalObfuscated)
        {
            if (hasEnoughKeywords)
            {
                string obfuscatedBanReason = $"Obfuscation detected, flagged as potential advertising spam message: \"{input}\" " + $"Matched: [{string.Join(", ", matchedKeywords)}]. " + $"TLD: {(globalEndingCheck ?? "None")}";
                if (useTimeout)
                {
                    if (!disableAllMessages)
                    {
                        if (sendAction)
                            CPH.SendAction(msgTimeOut, useBot, fallback);
                        else
                            CPH.SendMessage(msgTimeOut, useBot, fallback);
                    }

                    CPH.TwitchTimeoutUser(user, duration, obfuscatedBanReason, useBot);
                    CPH.LogInfo($"TLG LOG: Timed out '{user}' => obfuscated + enough keywords. Reason: {obfuscatedBanReason}");
                }
                else
                {
                    if (!disableAllMessages)
                    {
                        if (sendAction)
                            CPH.SendAction(msgObfuscatedBan, useBot, fallback);
                        else
                            CPH.SendMessage(msgObfuscatedBan, useBot, fallback);
                    }

                    CPH.TwitchBanUser(user, obfuscatedBanReason, useBot);
                    CPH.LogInfo($"TLG LOG: Banned '{user}' => obfuscated + enough keywords. Reason: {obfuscatedBanReason}");
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(globalEndingCheck))
                {
                    if (!disableAllMessages)
                    {
                        if (sendAction)
                            CPH.SendAction(msgObfuscated, useBot, fallback);
                        else
                            CPH.SendMessage(msgObfuscated, useBot, fallback);
                    }

                    CPH.TwitchDeleteChatMessage(messageId, true);
                }

                if (useTwitchWarnFlag)
                {
                    if (!disableAllMessages)
                        CPH.TwitchWarnUser(user, msgTwitchWarn);
                    CPH.LogInfo($"TLG LOG: Warned '{user}' => obfuscated link but not enough keywords");
                }
            }

            return true;
        }

		//----------------------------------------------------------------
		// 13) Handle Auto-Held Messages with Updated Logic
		//----------------------------------------------------------------
		if (!string.IsNullOrEmpty(messageId) && CPH.TwitchApproveAutoHeldMessage(messageId))
		{
			if (!IsValidTwitchUsername(user))
			{
				CPH.LogError($"TLG LOG: Invalid username detected: '{user}'. Skipping auto-held moderation.");
				return true;
			}

			try
			{
				string denyAutoReason = $"Flagged as potential advertising spam message: \"{input}\" " +
										$"Matched: [{string.Join(", ", matchedKeywords)}]. " +
										$"TLD: {(globalEndingCheck ?? "None")}";

				// ✅ Added Bot Spam Detection
				var mentionedUsers = Regex.Matches(input, @"@(\w+)").Cast<Match>().Select(m => m.Groups[1].Value.ToLowerInvariant()).ToList();
				if (mentionedUsers.Count > 0)
					{
						if (!disableAllMessages)
						{
							if (sendAction) CPH.SendAction(msgAutoDenyBan, useBot);
							else CPH.SendMessage(msgAutoDenyBan, useBot);
						}

						CPH.TwitchBanUser(user, denyAutoReason, useBot);
						CPH.LogInfo($"TLG LOG: Banned '{user}' => auto-held + {matchedKeywordCount} keywords. Reason: {denyAutoReason}");
					}

				if (!CPH.TwitchDenyAutoHeldMessage(messageId))
				{
					CPH.LogError($"TLG LOG: Failed to deny auto-held message with ID: {messageId}");
					return true;
				}

				CPH.TwitchDeleteChatMessage(messageId, useBot);

				if (hasEnoughKeywords)
				{
					if (useTimeout)
					{
						if (!disableAllMessages)
						{
							if (sendAction) CPH.SendAction(msgTimeOut, useBot);
							else CPH.SendMessage(msgTimeOut, useBot);
						}

						CPH.TwitchTimeoutUser(user, duration, denyAutoReason, useBot);
						CPH.LogInfo($"TLG LOG: Timed out '{user}' => auto-held + {matchedKeywordCount} keywords. Reason: {denyAutoReason}");
					}
					else
					{
						if (!disableAllMessages)
						{
							if (sendAction) CPH.SendAction(msgAutoDenyBan, useBot);
							else CPH.SendMessage(msgAutoDenyBan, useBot);
						}

						CPH.TwitchBanUser(user, denyAutoReason, useBot);
						CPH.LogInfo($"TLG LOG: Banned '{user}' => auto-held + {matchedKeywordCount} keywords. Reason: {denyAutoReason}");
					}
				}
				else if (!string.IsNullOrEmpty(globalEndingCheck))
				{
					if (!disableAllMessages)
					{
						if (sendAction) CPH.SendAction(msgUrlDelete, useBot);
						else CPH.SendMessage(msgUrlDelete, useBot);
					}

					if (useTwitchWarnFlag)
					{
						if (!disableAllMessages) CPH.TwitchWarnUser(user, msgTwitchWarn);
						CPH.LogInfo($"TLG LOG: Warned '{user}' => suspicious TLD '{globalEndingCheck}' but not enough keywords.");
					}

					CPH.LogInfo($"TLG LOG: Auto-held message denied and deleted for TLD '{globalEndingCheck}' without enough keywords.");
				}
				else
				{
					CPH.LogInfo($"TLG LOG: Auto-held message denied and deleted. No action taken (keywords/TLD insufficient).");
				}

				string category = args.ContainsKey("category") ? args["category"].ToString() : "Unknown category";
				string heldAt = args.ContainsKey("heldAt") ? args["heldAt"].ToString() : "Unknown time";
				CPH.LogInfo($"TLG LOG: AutoMod denied => user '{user}', rawInput='{input}', " +
							$"category='{category}', keywordsFound='{matchedKeywordCount}', " +
							$"TLD='{globalEndingCheck}'");
			}
			catch (Exception ex)
			{
				CPH.LogError($"TLG LOG: Error handling auto-held message for '{user}': {ex.Message}");
			}

			return true;
		}

        return true;
    }
}
