using System;
using System.Collections.Generic;
using System.Threading.Tasks;

public class CPHInline
{
    public bool Execute()
    {
        try
        {
            // Default permit time is 30 seconds
            int permitTime = 30;

            // Default labels for time (seconds and minutes)
            Dictionary<string, string> timeLabels = new Dictionary<string, string>
            {
                { "minute", "minute" },
                { "minutes", "minutes" },
                { "second", "second" },
                { "seconds", "seconds" }
            };

            // Default messages
            string grantMessage = "";
            string revokeMessage = "";
            string existingPermissionMessage = "";

            // Retrieve and set arguments
            permitTime = CPH.TryGetArg("permitTime", out int permitTimeArg) ? permitTimeArg : permitTime;
            timeLabels = CPH.TryGetArg("timeLabels", out string timeLabelsArg) ? ParseTimeLabels(timeLabelsArg) : timeLabels;
            grantMessage = CPH.TryGetArg("grantMessage", out string grantMsgArg) ? grantMsgArg : grantMessage;
            revokeMessage = CPH.TryGetArg("revokeMessage", out string revokeMsgArg) ? revokeMsgArg : revokeMessage;
            existingPermissionMessage = CPH.TryGetArg("existingPermissionMessage", out string existingPermMsgArg) ? existingPermMsgArg : existingPermissionMessage;

            // Retrieve the target user
            if (!CPH.TryGetArg("targetUser", out string userToGivePermitTo) || string.IsNullOrEmpty(userToGivePermitTo))
            {
                CPH.LogError("The 'targetUser' argument was not provided or is invalid.");
                return false;
            }

            string currentPermitUser = CPH.GetGlobalVar<string>("permitUser", false);

            // Retrieve additional arguments
            bool useBot = CPH.TryGetArg("useBot", out bool botArg) && botArg;
            bool sendAction = CPH.TryGetArg("sendAction", out bool actionArg) && actionArg;

            // Format the permitTime for display
            string permitTimeDisplay = FormatPermitTime(permitTime, timeLabels);

            // If permitTime is below 10 seconds, send a special message
            if (permitTime < 10)
            {
                string shortTimeMessage = "I see what you did there... Kappa Stop trolling your users! Permission time below 10 seconds is mean! DansGame ";
                if (sendAction)
                {
                    CPH.SendAction(shortTimeMessage, useBot);
                }
                else
                {
                    CPH.SendMessage(shortTimeMessage, useBot);
                }
                return true;
            }

            // Grant permission if no one else currently has it
            if (string.IsNullOrEmpty(currentPermitUser))
            {
                CPH.SetGlobalVar("permitUser", userToGivePermitTo, false);

                string formattedGrantMessage = grantMessage
                    .Replace("{user}", userToGivePermitTo)
                    .Replace("{permitTime}", permitTimeDisplay);

                if (sendAction)
                {
                    CPH.SendAction(formattedGrantMessage, useBot);
                }
                else
                {
                    CPH.SendMessage(formattedGrantMessage, useBot);
                }

                // Schedule permission revocation asynchronously
                RevokePermissionAsync(userToGivePermitTo, permitTime, revokeMessage, sendAction, useBot);
            }
            else
            {
                // Notify that someone else already has permission
                if (sendAction)
                {
                    CPH.SendAction(existingPermissionMessage, useBot);
                }
                else
                {
                    CPH.SendMessage(existingPermissionMessage, useBot);
                }
                return true;
            }

            return true;
        }
        catch (Exception ex)
        {
            CPH.LogError($"An error occurred: {ex.Message}");
            return false;
        }
    }

    // Asynchronously revoke permission after a delay
    private async void RevokePermissionAsync(string user, int permitTime, string revokeMessage, bool sendAction, bool useBot)
    {
        await Task.Delay(permitTime * 1000);

        CPH.SetGlobalVar("permitUser", "", false);
        string formattedRevokeMessage = revokeMessage.Replace("{user}", user);

        if (sendAction)
        {
            CPH.SendAction(formattedRevokeMessage, useBot);
        }
        else
        {
            CPH.SendMessage(formattedRevokeMessage, useBot);
        }
    }

    // Method to format the permit time as minutes or seconds with customizable labels
    private string FormatPermitTime(int timeInSeconds, Dictionary<string, string> timeLabels)
    {
        if (timeInSeconds >= 60)
        {
            int minutes = timeInSeconds / 60;
            string label = minutes == 1 ? timeLabels["minute"] : timeLabels["minutes"];
            return $"{minutes} {label}";
        }
        else
        {
            string label = timeInSeconds == 1 ? timeLabels["second"] : timeLabels["seconds"];
            return $"{timeInSeconds} {label}";
        }
    }

    // Method to parse the timeLabels argument into a dictionary
    private Dictionary<string, string> ParseTimeLabels(string timeLabelsArg)
    {
        var labels = new Dictionary<string, string>
        {
            { "minute", "minute" },
            { "minutes", "minutes" },
            { "second", "second" },
            { "seconds", "seconds" }
        };

        // Split the input string by ';' and remove empty entries
        var pairs = timeLabelsArg.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var pair in pairs)
        {
            // Split each pair by the first '=' character
            var index = pair.IndexOf('=');
            if (index > 0)
            {
                var key = pair.Substring(0, index).Trim();
                var value = pair.Substring(index + 1).Trim();
                if (labels.ContainsKey(key))
                {
                    labels[key] = value;
                }
            }
        }

        return labels;
    }
}
