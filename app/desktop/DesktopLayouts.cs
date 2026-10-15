namespace HfsBridge.Manager;

internal sealed partial class ManagerWindow
{
    private void BuildLayout()
    {
        Text = "HFS Bridge"; StartPosition = FormStartPosition.CenterScreen;
        var main = DesktopTheme.Frame(this, false, drives);
        DesktopTheme.Row(main,DesktopTheme.Text("Open a Mac disk image",30,true));
        var intro = DesktopTheme.Text("Create a writable copy and open your files in Windows Explorer.",13,muted:true);
        intro.Margin = new Padding(0,0,0,28); DesktopTheme.Row(main,intro);
        var card = DesktopTheme.Stack(0);
        DesktopTheme.Row(card, DesktopTheme.Text("IMAGE FILES", 8, true, true));
        DesktopTheme.Button(browse, "&Browse…"); DesktopTheme.Button(choose, "&Choose…");
        DesktopTheme.Row(card, DesktopTheme.Labeled("Source image", DesktopTheme.Pair(DesktopTheme.Field(source, "Source image", "Choose an existing Mac disk image"), browse, 108)));
        DesktopTheme.Row(card, DesktopTheme.Labeled("Save writable copy as", DesktopTheme.Pair(DesktopTheme.Field(output, "New writable image", "Choose a new .img filename"), choose, 108)));
        DesktopTheme.Button(inspect, "Inspect partitions");
        var letter = DesktopTheme.Labeled("Drive letter", DesktopTheme.Field(letters, "Drive letter"));
        var part = DesktopTheme.Labeled("Partition · optional", DesktopTheme.Pair(DesktopTheme.Field(partition, "Partition number", "Raw volume"), inspect, 210));
        partition.AccessibleDescription = "Leave blank for a raw HFS volume; otherwise enter the partition number from inspection.";
        DesktopTheme.Row(card, DesktopTheme.SettingsRow(letter, part));
        var note = DesktopTheme.Text("Your source image stays unchanged. Changes are saved in the new copy.", 9, muted: true);
        note.Margin = new Padding(0, 0, 0, 14); DesktopTheme.Row(card, note);
        DesktopTheme.Button(mount, "Mount copy", true); DesktopTheme.Button(unmount, "Unmount"); unmount.Enabled = false;
        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top, Margin = Padding.Empty, WrapContents = false };
        mount.Width = 154; unmount.Width = 112; actions.Controls.Add(mount); actions.Controls.Add(unmount);
        DesktopTheme.Row(card, actions); DesktopTheme.Row(main, DesktopTheme.Card(card));
        status.Text = "Ready · choose an image to get started";
        DesktopTheme.Status(main, status); DesktopTheme.Activity(main, log);
    }
}


