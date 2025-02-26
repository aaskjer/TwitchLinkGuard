using System;
using System.Linq;
using System.Text;
using System.Globalization;
using System.Collections.Generic;
using System.Text.RegularExpressions;

public class CPHInline
{
	private bool IsValidTwitchUsername(string username)
	{
		if (string.IsNullOrEmpty(username)) return false;

		string pattern = @"^[a-zA-Z0-9_]{4,25}$";
		return Regex.IsMatch(username, pattern);
	}

    ///////////////////////////////////////////////////////////////////////////////
    // Precompiled Regex patterns
    ///////////////////////////////////////////////////////////////////////////////
    private static readonly Regex UrlRegex = new Regex(
        @"((https?:\/\/)?([\w\-]+\.)+[a-zA-Z]{2,})(\/[\w\-.~:\/?#[\]@!$&'()*+,;=%]*)?",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    private static readonly Regex TwitchBlockedPattern = new Regex(@"\*\*\*", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex VoucherCodeRegex = new Regex(
        @"\b[A-Z0-9]{3,6}(?:-[A-Z0-9]{3,6}){2,5}\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

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
		var matches = MentionRegex.Matches(message)
								  .Cast<Match>() // Cast to IEnumerable<Match>
								  .Select(m => m.Value.TrimStart('@').ToLower())
								  .Distinct()
								  .ToList();
		return matches;
	}


    ///////////////////////////////////////////////////////////////////////////////
    // Removes combining/diacritical marks
    ///////////////////////////////////////////////////////////////////////////////
    private string RemoveDiacriticalMarks(string text)
    {
        if (string.IsNullOrEmpty(text))
            return text;

        // 1) Normalize to FormD (splits base characters and combining marks)
        string formD = text.Normalize(NormalizationForm.FormD);

        // 2) Keep only characters that are NOT in the combining mark categories
        StringBuilder sb = new StringBuilder();
        foreach (char c in formD)
        {
            UnicodeCategory uc = CharUnicodeInfo.GetUnicodeCategory(c);
            if (!CombiningMarkCategories.Contains(uc))
            {
                sb.Append(c);
            }
        }

        // 3) Normalize back to FormC
        return sb.ToString().Normalize(NormalizationForm.FormC);
    }

    ///////////////////////////////////////////////////////////////////////////////
    // Returns a list of which suspicious keywords were matched in the input
    ///////////////////////////////////////////////////////////////////////////////
    private List<string> GetMatchedKeywords(string input, List<string> keywords)
    {
        // Remove diacritics
        string normalizedInput = RemoveDiacriticalMarks(input);

        // Optionally remove URLs from the input so partial URL matches don’t trigger
        string inputWithoutUrls = UrlRegex.Replace(normalizedInput, "");

        var matchedKeywords = new List<string>();
        foreach (string keyword in keywords)
        {
            // Normalize the keyword itself
            string normalizedKeyword = RemoveDiacriticalMarks(keyword);

            // Word-boundary pattern
            string pattern = @"(?<!\w)" + Regex.Escape(normalizedKeyword) + @"(?!\w)";

            // Find all occurrences
            MatchCollection matches = Regex.Matches(
                inputWithoutUrls,
                pattern,
                RegexOptions.IgnoreCase | RegexOptions.Compiled
            );

            // If we found at least 1 match, record this keyword
            if (matches.Count > 0)
            {
                // Use the *original* keyword for clarity (exact text from suspiciousKeywords)
                matchedKeywords.Add(keyword);
            }
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
            {
                return true;
            }
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
                {
                    return ending;
                }
            }
        }

        foreach (string ending in suspiciousEndings)
        {
            string pattern = $@"\b{Regex.Escape(ending)}\b";
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
            {
                return ending;
            }
        }

        return null;
    }

    ///////////////////////////////////////////////////////////////////////////////
    // Checks messages for obfuscation patterns
    ///////////////////////////////////////////////////////////////////////////////
    private bool IsObfuscatedMessage(string message, List<string> suspiciousEndings)
    {
        string tldPattern = string.Join("|", suspiciousEndings).Replace(".", "");
        string obfuscationPattern =
            @"\b[\w\-]+(?:[\s\[\]{}()]*dot[\s\[\]{}()]*|[\s\[\]{}()]*\.[\s\[\]{}()]*)(?:" + tldPattern + @")\b";

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
    // Checks if a message contains '***' (blocked URL by Twitch)
    ///////////////////////////////////////////////////////////////////////////////
    private bool IsBlockedByTwitch(string message)
    {
        return TwitchBlockedPattern.IsMatch(message);
    }

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
			// Example placeholder for additional actions
			CPH.LogDebug($"TLG LOG: Successfully validated and prepared user '{user}'.");
		}
		catch (Exception ex)
		{
			CPH.LogError($"TLG LOG: Unexpected error while processing user '{user}': {ex.Message}");
			return true; // Safely stop further processing
		}

        // Possibly retrieve a permit user if you’re using that system
        string permitUser = CPH.GetGlobalVar<string>("permitUser", false);

        bool sendAction = false;
        CPH.TryGetArg("sendAction", out sendAction);

        bool fallback = args.ContainsKey("fallback") ? bool.Parse(args["fallback"].ToString()) : true;

        bool useBot = false;
        CPH.TryGetArg("useBot", out useBot);

        // Roles
        bool isModerator   = false;
        bool isVip         = false;
        bool isSubscribed  = false;

        CPH.TryGetArg("isSubscribed", out isSubscribed);
        CPH.TryGetArg("isVip", out isVip);
        CPH.TryGetArg("isModerator", out isModerator);

        // Whether to skip moderation for VIP or Sub
        bool skipVipModeration = true;  // default => VIP exempt
        bool skipSubModeration = false; // default => Sub is not exempt
        if (args.ContainsKey("skipVipModeration"))
            skipVipModeration = Convert.ToBoolean(args["skipVipModeration"]);
        if (args.ContainsKey("skipSubModeration"))
            skipSubModeration = Convert.ToBoolean(args["skipSubModeration"]);

        // Additional roles checks
        CPH.TryGetArg("groupName", out string groupName);
        CPH.TryGetArg("userName", out string userName);

        // If `useTimeout = true`, we do timeouts. If false, we do bans.
        bool useTimeout = false;
        if (args.ContainsKey("useTimeout"))
        {
            useTimeout = Convert.ToBoolean(args["useTimeout"]);
        }

        // For timeouts
        int duration = 600; // default = 10 minutes
        if (args.ContainsKey("duration"))
        {
            duration = Convert.ToInt32(args["duration"]);
        }

        //----------------------------------------------------------------
        // 2) requiredKeywordCount
        //----------------------------------------------------------------
        int requiredKeywordCount = 2; // default => must have at least 2 suspicious keywords
        if (args.ContainsKey("requiredKeywordCount"))
        {
            requiredKeywordCount = Convert.ToInt32(args["requiredKeywordCount"]);
        }

        //----------------------------------------------------------------
        // 3) Check trusted groups, bot user, mod, etc.
        //----------------------------------------------------------------

        // a) Check group
        bool userInGroup = false;
        if (!string.IsNullOrEmpty(groupName))
        {
            string[] groups = groupName
                .Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(g => g.Trim())
                .ToArray();

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

        // b) Check if user is the bot
        var botInfo = CPH.TwitchGetBot();
        string botName = botInfo?.UserName ?? "";
        if (!string.IsNullOrEmpty(botName) && user.Equals(botName, StringComparison.OrdinalIgnoreCase))
        {
            CPH.LogDebug($"TLG LOG: '{user}' is the Streamer.bot bot => skip moderation.");
            return true;
        }

        // c) Moderator => skip
        if (isModerator)
        {
            CPH.LogDebug($"TLG LOG: '{user}' is a Moderator => skip moderation.");
            return true;
        }

        // d) Time-based permit => skip
        if (!string.IsNullOrEmpty(permitUser) && user.Equals(permitUser, StringComparison.OrdinalIgnoreCase))
        {
            CPH.LogDebug($"TLG LOG: '{user}' has a permit => skip moderation.");
            return true;
        }

        // e) VIP => skip if skipVipModeration = true
        if (isVip && skipVipModeration)
        {
            CPH.LogDebug($"TLG LOG: '{user}' is VIP + skipVipModeration => skip.");
            return true;
        }

        // f) Sub => skip if skipSubModeration = true
        if (isSubscribed && skipSubModeration)
        {
            CPH.LogDebug($"TLG LOG: '{user}' is Subscribed + skipSubModeration => skip.");
            return true;
        }

        //----------------------------------------------------------------
        // 4) Parse suspiciousKeywords, suspiciousEndings, whitelist
        //----------------------------------------------------------------
        List<string> suspiciousKeywords = new List<string>();
        List<string> suspiciousEndings  = new List<string>();
        List<string> whitelist          = new List<string>();

        // suspiciousKeywords
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

        // suspiciousEndings
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

        // whitelist
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

        // Check if we should also do TwitchWarn
        bool useTwitchWarnFlag = args.ContainsKey("useTwitchWarn")
                              && bool.TryParse(args["useTwitchWarn"]?.ToString(), out var globalWarnFlag)
                              && globalWarnFlag;

        //----------------------------------------------------------------
        // 5) Count suspicious keywords
        //----------------------------------------------------------------
        List<string> matchedKeywords = GetMatchedKeywords(input, suspiciousKeywords);
        int matchedKeywordCount      = matchedKeywords.Count;
        bool hasEnoughKeywords       = (matchedKeywordCount >= requiredKeywordCount);

        // Debugging
        CPH.LogDebug(
            $"TLG LOG: Found {matchedKeywordCount} suspicious keyword(s): " +
            $"[{string.Join(", ", matchedKeywords)}]. " +
            $"Required for ban/timeout={requiredKeywordCount}. Enough? {hasEnoughKeywords}"
        );

        //----------------------------------------------------------------
        // 6) Check suspicious TLD + obfuscation
        //----------------------------------------------------------------
        string globalEndingCheck = GetSuspiciousEnding(input, suspiciousEndings);
        bool globalObfuscated    = IsObfuscatedMessage(input, suspiciousEndings);

        //----------------------------------------------------------------
        // 7) Additional messages
        //----------------------------------------------------------------
		// Get the flag for disabling chat messages.
		bool disableAllMessages = args.ContainsKey("disableAllMessages") && Convert.ToBoolean(args["disableAllMessages"]);

		// Prepare message templates with replacement.
		string msgVoucherBanTemplate    = args.ContainsKey("msgVoucherBan") ? args["msgVoucherBan"].ToString() : "";
		string msgVoucherBan            = msgVoucherBanTemplate.Replace("{user}", user);
		string msgUrlDeleteTemplate     = args.ContainsKey("msgUrlDelete") ? args["msgUrlDelete"].ToString() : "";
		string msgUrlDelete             = msgUrlDeleteTemplate.Replace("{user}", user);
		string msgUrlBanTemplate        = args.ContainsKey("msgUrlBan") ? args["msgUrlBan"].ToString() : "";
		string msgUrlBan                = msgUrlBanTemplate.Replace("{user}", user);
		string msgObfuscatedTemplate    = args.ContainsKey("msgObfuscated") ? args["msgObfuscated"].ToString() : "";
		string msgObfuscated            = msgObfuscatedTemplate.Replace("{user}", user);
		string msgObfuscatedBanTemplate = args.ContainsKey("msgObfuscatedBan") ? args["msgObfuscatedBan"].ToString() : "";
		string msgObfuscatedBan         = msgObfuscatedBanTemplate.Replace("{user}", user);
		string msgIsBlockedTemplate     = args.ContainsKey("msgIsBlocked") ? args["msgIsBlocked"].ToString() : "";
		string msgIsBlocked             = msgIsBlockedTemplate.Replace("{user}", user);
		string msgIsBlockedBanTemplate  = args.ContainsKey("msgIsBlockedBan") ? args["msgIsBlockedBan"].ToString() : "";
		string msgIsBlockedBan          = msgIsBlockedBanTemplate.Replace("{user}", user);
		string msgAutoDenyBanTemplate   = args.ContainsKey("msgAutoDenyBan") ? args["msgAutoDenyBan"].ToString() : "";
		string msgAutoDenyBan           = msgAutoDenyBanTemplate.Replace("{user}", user);
		string msgTwitchWarnTemplate    = args.ContainsKey("msgTwitchWarn") ? args["msgTwitchWarn"].ToString() : "";
		string msgTwitchWarn            = msgTwitchWarnTemplate.Replace("{user}", user);
		string msgTimeOutTemplate       = args.ContainsKey("msgTimeOut") ? args["msgTimeOut"].ToString() : "";
		string msgTimeOut               = msgTimeOutTemplate.Replace("{user}", user).Replace("{duration}", duration.ToString());
		string msgMentionTimeOutTemplate = args.ContainsKey("msgMentionTimeOut") ? args["msgMentionTimeOut"].ToString() : "";
		string msgMentionTimeOut        = msgMentionTimeOutTemplate.Replace("{user}", user).Replace("{duration}", duration.ToString());
		string msgMentionBanTemplate    = args.ContainsKey("msgMentionBan") ? args["msgMentionBan"].ToString() : "";
		string msgMentionBan            = msgMentionBanTemplate.Replace("{user}", user);


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
					// Build reason
					string voucherReason = $"Voucher-Code detected. Message: \"{input}\" " +
										   $"Matched: [{string.Join(", ", matchedKeywords)}]. " +
										   $"TLD: {(globalEndingCheck ?? "None")}";

					// If useTimeout => do timeout. Otherwise => ban
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
					// Possibly just warn or skip
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
		if (IsBlockedByTwitch(input))
		{
			if (hasEnoughKeywords)
			{
				string blockedBanReason =
					$"Flagged as potential advertising spam message: \"{input}\"" +
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
				return true;
			}
			else
			{
				// Just delete or warn
				CPH.TwitchDeleteChatMessage(messageId, true);
				if (!disableAllMessages)
				{
					if (sendAction)
						CPH.SendAction(msgIsBlocked, useBot, fallback);
					else
						CPH.SendMessage(msgIsBlocked, useBot, fallback);
				}

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

				// If whitelisted => skip entirely
				if (IsWhitelistedUrl(url, whitelist))
				{
					CPH.LogInfo($"TLG LOG: URL '{url}' is whitelisted => skip moderation.");
					return true;
				}

				// If hasEnoughKeywords => ban or timeout
				if (hasEnoughKeywords)
				{
					// Build reason
					string reason =
						$"Flagged as potential advertising spam message: \"{input}\" " +
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
					// Not enough keywords for ban or timeout
					// If TLD is suspicious => maybe delete or warn
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
						// Otherwise skip or do nothing
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
			// Extract mentioned usernames from the message
			var mentionedUsers = Regex.Matches(input, @"@(\w+)")
									  .Cast<Match>()
									  .Select(m => m.Groups[1].Value.ToLowerInvariant())
									  .ToList();

			if (mentionedUsers.Count > 0)
			{
				// Since we don't have CPH.TwitchGetChatUsers(), just compare against "user"
				bool mentionedNonPresentUser = mentionedUsers.Any(mentionedUser => !mentionedUser.Equals(user, StringComparison.OrdinalIgnoreCase));

				if (mentionedNonPresentUser)
				{
					// Construct a reason for the action
					string mentionBanReason =
						$"Mentioned non-present users: [{string.Join(", ", mentionedUsers)}] in message: \"{input}\" " +
						$"Matched keywords: [{string.Join(", ", matchedKeywords)}]. " +
						$"TLD: {(globalEndingCheck ?? "None")}";

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
				string obfuscatedBanReason =
					$"Obfuscation detected, flagged as potential advertising spam message: \"{input}\" " +
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
				// Possibly delete or warn
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
			// Validate user
			if (!IsValidTwitchUsername(user))
			{
				CPH.LogError($"TLG LOG: Invalid username detected: '{user}'. Skipping auto-held moderation.");
				return true;
			}

			try
			{
				// Construct the reason for denial
				string denyAutoReason =
					$"Flagged as potential advertising spam message: \"{input}\" " +
					$"Matched: [{string.Join(", ", matchedKeywords)}]. " +
					$"TLD: {(globalEndingCheck ?? "None")}";

				// Explicitly deny the auto-held message
				if (!CPH.TwitchDenyAutoHeldMessage(messageId))
				{
					CPH.LogError($"TLG LOG: Failed to deny auto-held message with ID: {messageId}");
					return true;
				}

				// Delete the denied message
				CPH.TwitchDeleteChatMessage(messageId, useBot);

				// Check for sufficient keywords or suspicious TLD
				if (hasEnoughKeywords)
				{
					if (useTimeout)
					{
						if (!disableAllMessages)
						{
							if (sendAction)
								CPH.SendAction(msgTimeOut, useBot, fallback);
							else
								CPH.SendMessage(msgTimeOut, useBot, fallback);
						}
						CPH.TwitchTimeoutUser(user, duration, denyAutoReason, useBot);
						CPH.LogInfo($"TLG LOG: Timed out '{user}' => auto-held + {matchedKeywordCount} keywords. Reason: {denyAutoReason}");
					}
					else
					{
						if (!disableAllMessages)
						{
							if (sendAction)
								CPH.SendAction(msgAutoDenyBan, useBot, fallback);
							else
								CPH.SendMessage(msgAutoDenyBan, useBot, fallback);
						}
						CPH.TwitchBanUser(user, denyAutoReason, useBot);
						CPH.LogInfo($"TLG LOG: Banned '{user}' => auto-held + {matchedKeywordCount} keywords. Reason: {denyAutoReason}");
					}
				}
				else if (!string.IsNullOrEmpty(globalEndingCheck))
				{
					if (!disableAllMessages)
					{
						if (sendAction)
							CPH.SendAction(msgUrlDelete, useBot, fallback);
						else
							CPH.SendMessage(msgUrlDelete, useBot, fallback);
					}
					if (useTwitchWarnFlag)
					{
						if (!disableAllMessages)
							CPH.TwitchWarnUser(user, msgTwitchWarn);
						CPH.LogInfo($"TLG LOG: Warned '{user}' => suspicious TLD '{globalEndingCheck}' but not enough keywords.");
					}
					CPH.LogInfo($"TLG LOG: Auto-held message denied and deleted for TLD '{globalEndingCheck}' without enough keywords.");
				}
				else
				{
					CPH.LogInfo($"TLG LOG: Auto-held message denied and deleted. No action taken (keywords/TLD insufficient).");
				}

				// Log additional context
				string category = args.ContainsKey("category") ? args["category"].ToString() : "Unknown category";
				string heldAt = args.ContainsKey("heldAt") ? args["heldAt"].ToString() : "Unknown time";
				CPH.LogInfo(
					$"TLG LOG: AutoMod denied => user '{user}', rawInput='{input}', " +
					$"category='{category}', keywordsFound='{matchedKeywordCount}', " +
					$"TLD='{globalEndingCheck}'"
				);
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
