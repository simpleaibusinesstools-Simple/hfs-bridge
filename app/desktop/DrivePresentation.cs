namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    internal bool ReturnToImages { get; private set; }
    private readonly Button readOnlyMode = new ThemeButton(), writableMode = new ThemeButton();
    private readonly Label driveTitle = new(), driveModel = new(), connectionText = new(), capacityText = new(), formatText = new(), busText = new(), letterText = new(), transferHint = new();
    private readonly Control connectionDot = new StatusLight();
    private string? previewTitle;
    private bool previewState;
    internal void ShowStartupFromHeader() => OpenStartupSettings();

    private void BuildLayout()
    {
        Text = "HFS Bridge · Drives"; StartPosition = FormStartPosition.CenterScreen;
        var back = new ThemeButton(); back.Click += (_,_) =>
        {
            if (host != null || transferActive) { status.Text = "Close the drive before switching to disk images"; return; }
            ReturnToImages = Owner == null; Close();
        };
        var main = DesktopTheme.Frame(this,true,back);
        var workspace = new ReferencePanel(1384,856);
        Label Label(string text, float points, bool bold = false, bool muted = false)
        { var label = DesktopTheme.Text(text,points,bold,muted); label.AutoSize = false; label.AutoEllipsis = true; return label; }
        workspace.Place(Label("C O N N E C T E D   D R I V E",11,false,true),0,20,750,28,11);
        driveTitle.Text = "Your Mac drive"; driveTitle.Font = new Font("Segoe UI",46,FontStyle.Bold); driveTitle.ForeColor = DesktopTheme.Ink;
        driveTitle.BackColor = Color.Transparent; driveTitle.AutoEllipsis = true;
        workspace.Place(driveTitle,0,53,754,83,46);
        driveModel.Font = new Font("Segoe UI",22); driveModel.ForeColor = DesktopTheme.Muted; driveModel.BackColor = Color.Transparent; driveModel.AutoEllipsis = true;
        workspace.Place(driveModel,0,128,754,46,22);
        connectionText.Font = new Font("Segoe UI",17); connectionText.ForeColor = DesktopTheme.Muted; connectionText.BackColor = Color.Transparent;
        workspace.Place(connectionDot,2,182,18,18); workspace.Place(connectionText,36,174,714,36,17);
        var selector = new DesktopTheme.BorderedPanel { BackColor = DesktopTheme.Surface };
        workspace.Place(selector,788,45,596,122);
        var selectorLayout = new ReferencePanel(596,122) { Dock = DockStyle.Fill };
        selectorLayout.Place(DesktopTheme.Picture("drive-thumbnail"),16,10,142,104);
        disks.AccessibleName = "Connected external drive"; disks.Font = new Font("Segoe UI",16,FontStyle.Bold);
        disks.ForeColor = DesktopTheme.Ink; disks.BackColor = DesktopTheme.Surface; disks.FlatStyle = FlatStyle.Flat;
        disks.DropDownStyle = ComboBoxStyle.DropDownList; disks.DrawMode = DrawMode.OwnerDrawFixed;
        disks.ItemHeight = 32;
        selectorLayout.Place(disks,176,26,406,38,16);
        selectorLayout.Place(Label("Select your connected Mac drive",14,false,true),180,70,398,30,14);
        selector.Controls.Add(selectorLayout);
        var facts = new DesktopTheme.BorderedPanel { BackColor = DesktopTheme.Surface };
        workspace.Place(facts,0,222,1384,115);
        var factLayout = new ReferencePanel(1384,115) { Dock = DockStyle.Fill };
        void Fact(string icon, Label value, string caption, int x)
        {
            factLayout.Place(DesktopTheme.Picture("icon-"+icon+"-light"),x+52,33,44,44);
            value.Font = new Font("Segoe UI",20,FontStyle.Bold); value.ForeColor = DesktopTheme.Ink; value.BackColor = Color.Transparent;
            int valueWidth = Math.Min(220,1384-x-124);
            factLayout.Place(value,x+124,25,valueWidth,40,20);
            factLayout.Place(Label(caption,15,false,true),x+124,64,valueWidth,32,15);
            if (x > 0) factLayout.Place(new Panel { BackColor = DesktopTheme.Line },x,27,1,60);
        }
        Fact("hard_drive",capacityText,"Capacity",0); Fact("layer",formatText,"Format",326);
        Fact("plug_connected",busText,"Connection",676); Fact("hard_drive",letterText,"Opens as",1056);
        facts.Controls.Add(factLayout);
        workspace.Place(Label("A C C E S S   M O D E",11,false,true),0,369,664,28,11);
        DesktopTheme.Button(readOnlyMode,"Read-only"); DesktopTheme.Icon(readOnlyMode,"lock_closed");
        DesktopTheme.Button(writableMode,"Read & write"); DesktopTheme.Icon(writableMode,"lock_open");
        ((ThemeButton)readOnlyMode).PreserveDisabledColors = ((ThemeButton)writableMode).PreserveDisabledColors = true;
        ((ThemeButton)readOnlyMode).SelectedIcon = DesktopTheme.Art("icon-lock_closed-ink");
        ((ThemeButton)writableMode).SelectedIcon = DesktopTheme.Art("icon-lock_open-ink");
        readOnlyMode.AccessibleRole = writableMode.AccessibleRole = AccessibleRole.RadioButton;
        workspace.Place(readOnlyMode,0,405,292,68,16); workspace.Place(writableMode,298,405,370,68,16);
        allowChanges.Text = "Allow changes on this drive"; allowChanges.CheckedChanged += (_,_) => UpdateControls();
        readOnlyMode.Click += (_,_) => { if (allowChanges.Enabled) allowChanges.Checked = false; };
        writableMode.Click += (_,_) => { if (allowChanges.Enabled) allowChanges.Checked = true; };
        DesktopTheme.Button(openDrive,"Open drive",true); DesktopTheme.Icon(openDrive,"folder","ink");
        DesktopTheme.Button(showFiles,"Open in Explorer",true); DesktopTheme.Icon(showFiles,"folder","ink");
        workspace.Place(openDrive,712,394,432,84,23); workspace.Place(showFiles,712,394,432,84,23);
        DesktopTheme.Button(refresh,"Refresh"); DesktopTheme.Icon(refresh,"arrow_clockwise");
        DesktopTheme.Button(unmount,"Close safely"); DesktopTheme.Icon(unmount,"lock_closed");
        workspace.Place(refresh,1172,405,212,68,16); workspace.Place(unmount,1172,405,212,68,16);
        openDescription.AutoSize = false; openDescription.ForeColor = DesktopTheme.Muted; openDescription.Font = new Font("Segoe UI",14); openDescription.BackColor = Color.Transparent;
        workspace.Place(openDescription,0,487,668,55,14);
        workspace.Place(Label("Opens your files in Windows Explorer.",14,false,true),712,488,672,50,14);
        workspace.Place(new Panel { BackColor = DesktopTheme.Line },0,548,1384,1);
        workspace.Place(DesktopTheme.Picture("transfer-illustration"),22,599,418,173);
        workspace.Place(new Panel { BackColor = DesktopTheme.Line },473,582,1,164);
        workspace.Place(Label("Move a large file, faster",27,true),522,574,860,53,27);
        workspace.Place(Label("Copy a Windows file to your Mac drive in one verified transfer.",16,false,true),522,626,860,44,16);
        DesktopTheme.Button(fastTransfer,"Choose a file"); DesktopTheme.Icon(fastTransfer,"document");
        workspace.Place(fastTransfer,522,676,382,72,17);
        transferHint.ForeColor = DesktopTheme.Muted; transferHint.Font = new Font("Segoe UI",13); transferHint.BackColor = Color.Transparent; transferHint.UseMnemonic = false;
        workspace.Place(DesktopTheme.Picture("icon-info-light"),976,704,28,28);
        workspace.Place(transferHint,1020,690,360,61,13);
        var dock = new DesktopTheme.BorderedPanel { BackColor = DesktopTheme.Surface };
        workspace.Place(dock,0,781,1384,72);
        var dockLayout = new ReferencePanel(1384,72) { Dock = DockStyle.Fill };
        dockLayout.Place(DesktopTheme.Picture("icon-hard_drive-light"),24,22,30,30);
        status.ForeColor = DesktopTheme.Ink; status.Font = new Font("Segoe UI",13); status.BackColor = Color.Transparent;
        status.AccessibleName = "Drive status"; status.AutoEllipsis = false;
        dockLayout.Place(status,82,13,880,51,13);
        var activityToggle = new ThemeButton(); DesktopTheme.Button(activityToggle,"Activity"); DesktopTheme.Icon(activityToggle,"document");
        var advancedToggle = new ThemeButton(); DesktopTheme.Button(advancedToggle,"Advanced"); DesktopTheme.Icon(advancedToggle,"settings");
        foreach (var button in new[] { activityToggle,advancedToggle }) button.FlatAppearance.BorderSize = 0;
        dockLayout.Place(activityToggle,977,10,180,52,13); dockLayout.Place(advancedToggle,1165,10,205,52,13);
        dock.Controls.Add(dockLayout); DesktopTheme.Row(main,workspace);
        var activityPanel = DesktopTheme.ActivityPanel(log); activityPanel.Visible = false; DesktopTheme.Row(main,activityPanel);
        activityToggle.Click += (_,_) => { activityPanel.Visible = !activityPanel.Visible; activityToggle.Text = activityPanel.Visible ? "Hide activity" : "Activity"; };
        var advanced = DesktopTheme.Stack(0);
        DesktopTheme.Row(advanced,DesktopTheme.Text("ADVANCED DRIVE OPTIONS",10,true,true));
        details.AutoSize = true; details.ForeColor = DesktopTheme.Muted; details.Font = new Font("Segoe UI",10);
        DesktopTheme.Row(advanced,details);
        DesktopTheme.Button(inspect,"Inspect partitions");
        DesktopTheme.Row(advanced,DesktopTheme.Labeled("HFS+ / HFSX partition",DesktopTheme.Pair(DesktopTheme.Field(partitions,"Partition"),inspect,180)));
        DesktopTheme.Button(checkVolume,"Check filesystem (read-only)");
        var letter = DesktopTheme.Labeled("Drive letter",DesktopTheme.Field(letters,"Drive letter"));
        var check = DesktopTheme.Stack(0); DesktopTheme.Row(check,DesktopTheme.Text("Before mounting",10,true)); DesktopTheme.Row(check,checkVolume);
        DesktopTheme.Row(advanced,DesktopTheme.SettingsRow(letter,check));
        consent.Text = "I have protected my files and want to make changes directly on this drive.";
        reconnect.Text = "Mount again after reconnect, while this window is open.";
        foreach (var box in new[] { consent,reconnect }) { box.AutoSize = true; box.Margin = new Padding(0,0,0,12); box.ForeColor = DesktopTheme.TextColor; DesktopTheme.Row(advanced,box); }
        DesktopTheme.Button(mount,"Mount with changes"); mount.Width = 210;
        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top }; actions.Controls.Add(mount); DesktopTheme.Row(advanced,actions);
        advancedOptions = DesktopTheme.Card(advanced); advancedOptions.Visible = false; DesktopTheme.Row(main,advancedOptions);
        advancedToggle.Click += (_,_) => { advancedOptions.Visible = !advancedOptions.Visible; advancedToggle.Text = advancedOptions.Visible ? "Hide advanced" : "Advanced"; };
        status.TextChanged += (_,_) => { if (!previewState) RefreshWorkspaceState(); status.ForeColor = DesktopTheme.Failure(status.Text) && !DesktopTheme.HighContrast ? Color.FromArgb(255,186,151) : DesktopTheme.TextColor; };
        showFiles.EnabledChanged += (_,_) => { if (!previewState) RefreshWorkspaceState(); };
        unmount.EnabledChanged += (_,_) => { if (!previewState) RefreshWorkspaceState(); };
        letters.SelectedIndexChanged += (_,_) => RefreshWorkspaceState();
    }
    private void RefreshWorkspaceState()
    {
        if (previewState) return;
        var disk = disks.SelectedItem as DiskItem;
        driveTitle.Text = previewTitle ?? (partitions.SelectedItem is DiskPartition { Name.Length: > 0 } part ? part.Name : disk == null ? "Connect your Mac drive" : "Your Mac drive");
        driveModel.Text = disk?.FriendlyName ?? "HFS+ and HFSX drives · no reformatting";
        connectionText.Text = disk == null ? "Waiting for a connected drive" : DesktopTheme.Failure(status.Text) ? "Needs attention · see Activity" : showFiles.Enabled ? "Open in Windows" : "Connected";
        connectionDot.ForeColor = disk == null ? DesktopTheme.Muted : DesktopTheme.Failure(status.Text) ? Color.FromArgb(255,186,151) : DesktopTheme.Accent;
        capacityText.Text = disk == null ? "—" : disk.Size >= 1_000_000_000_000 ? $"{disk.Size/1_000_000_000_000.0:0.##} TB" : $"{disk.Size/1_000_000_000.0:0.#} GB";
        formatText.Text = volume?.Signature == 0x4858 ? "HFSX" : volume != null ? "HFS+" : "Not checked";
        busText.Text = disk == null ? "—" : disk.FriendlyName.Contains("USB 3.0",StringComparison.OrdinalIgnoreCase) ? "USB 3.0" : disk.BusType;
        letterText.Text = mountedLetter ?? letters.SelectedItem?.ToString() ?? "—";
        readOnlyMode.Enabled = writableMode.Enabled = allowChanges.Enabled;
        bool writable = host != null ? !readOnlyHost : openingReadOnly ? openingForWrite : allowChanges.Checked;
        void Mode(Button button, bool selected)
        {
            ((ThemeButton)button).UseSelectedIcon = selected;
            button.BackColor = DesktopTheme.HighContrast ? selected ? SystemColors.Highlight : SystemColors.Control : selected ? DesktopTheme.Accent : DesktopTheme.Surface;
            button.ForeColor = DesktopTheme.HighContrast ? selected ? SystemColors.HighlightText : SystemColors.ControlText : selected ? Color.FromArgb(4,29,37) : DesktopTheme.Muted;
            button.AccessibleDescription = selected ? "Selected access mode" : "Select before opening the drive";
            button.Invalidate();
        }
        Mode(readOnlyMode,!writable); Mode(writableMode,writable);
        openDrive.Visible = !showFiles.Enabled; showFiles.Visible = showFiles.Enabled;
        refresh.Visible = !unmount.Enabled; unmount.Visible = unmount.Enabled;
        fastTransfer.Text = transferAfterClose != null ? "Closing safely…" : host != null ? "Close & transfer" : "Choose a file";
        fastTransfer.AccessibleName = fastTransfer.Text;
        transferHint.Text = transferAfterClose != null ? "Close files and Explorer windows using this drive." : host != null ?
            "Closes safely, then opens the file picker." : !allowChanges.Checked ?
            "You'll be asked to allow writing for this transfer." : "Your saved copy is verified automatically.";
    }
    // Rendering fixtures only; no discovery, host, physical IO or saved profile changes.
    internal void PreviewWorkspace(string state)
    {
        var disk = new DiskItem(1,"TOSHIBA External USB 3.0","USB",2000398931968,"PREVIEW",512,512,false,false,false,false);
        if (state != "empty") { inventory = new DriveInventory([disk],[],false); disks.Items.Add(disk); disks.SelectedIndex = 0; previewTitle = "Youtube Project"; }
        UpdateControls(); RefreshWorkspaceState();
        if (state != "empty") formatText.Text = "HFS+";
        previewState = true;
        if (state == "hover") ((ThemeButton)readOnlyMode).HoverForValidation();
        if (state == "writable") { allowChanges.Checked = true; ((ThemeButton)readOnlyMode).UseSelectedIcon = false; ((ThemeButton)writableMode).UseSelectedIcon = true; readOnlyMode.BackColor = DesktopTheme.Surface; readOnlyMode.ForeColor = DesktopTheme.Muted; writableMode.BackColor = DesktopTheme.Accent; writableMode.ForeColor = Color.FromArgb(4,29,37); fastTransfer.Enabled = true; transferHint.Text = "Your saved copy is verified automatically."; }
        if (state is "mounted" or "busy")
        {
            readOnlyMode.Enabled = writableMode.Enabled = false; openDrive.Enabled = refresh.Enabled = disks.Enabled = fastTransfer.Enabled = false;
            readOnlyMode.BackColor = DesktopTheme.Accent; readOnlyMode.ForeColor = Color.FromArgb(4,29,37); writableMode.BackColor = DesktopTheme.Surface; writableMode.ForeColor = DesktopTheme.Muted;
            if (state == "mounted") { openDrive.Visible = false; showFiles.Visible = true; showFiles.Enabled = true; refresh.Visible = false; unmount.Visible = true; unmount.Enabled = true; status.Text = "Mounted at Z: · copy files to Windows · source protected"; connectionText.Text = "Open in Windows"; fastTransfer.Enabled = true; fastTransfer.Text = "Close & transfer"; transferHint.Text = "Closes safely, then opens the file picker."; }
            else status.Text = "Opening your drive · checking its identity and filesystem…";
        }
        if (state == "error") { status.Text = "Host failed · stale mount closed; check the drive before reopening"; connectionText.Text = "Needs attention · see Activity"; connectionDot.ForeColor = Color.FromArgb(255,186,151); log.Text = "The drive connection was lost. Close the drive safely, reconnect it, then inspect before trying again."; }
    }
    private void ValidatePresentationModes(List<string> checks)
    {
        void Require(bool value) { if (!value) throw new IOException("Access-mode presentation changed controller behavior."); }
        Require(!allowChanges.Checked && readOnlyMode.Enabled && writableMode.Enabled && fastTransfer.Enabled);
        ((ThemeButton)writableMode).ClickForValidation();
        Require(allowChanges.Checked && fastTransfer.Enabled && openDescription.Text.Contains("both ways",StringComparison.Ordinal));
        ((ThemeButton)readOnlyMode).ClickForValidation();
        Require(!allowChanges.Checked && fastTransfer.Enabled && openDescription.Text.Contains("protected",StringComparison.Ordinal));
        allowChanges.Enabled = false;
        ((ThemeButton)writableMode).ClickForValidation(); Require(!allowChanges.Checked);
        UpdateControls();
        checks.Add("native access-mode clicks select the existing controller permission and transfer state; disabled permission blocks selection");
    }
}

