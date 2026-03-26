$files = Get-ChildItem -Path . -Filter *.html

foreach ($file in $files) {
    $content = Get-Content -Path $file.FullName -Raw
    $originalContent = $content
    $updated = $false

    # 1. Replace existing lang-dropdown
    if ($content -match 'class="lang-dropdown"') {
        $content = $content -replace '(?s)<div class="lang-dropdown">.*?</div>', '<div id="google_translate_element"></div>'
        $updated = $true
    } 
    # 2. If no lang-dropdown but header-right exists
    elseif ($content -match 'class="header-right"' -and $content -notmatch 'id="google_translate_element"') {
         $content = $content -replace '(?s)<div class="header-right">', "<div class=`"header-right`">`n                <div id=`"google_translate_element`"></div>"
         $updated = $true
    }
    # 3. If no lang-dropdown but nav-right exists
    elseif ($content -match 'class="nav-right"' -and $content -notmatch 'id="google_translate_element"') {
         $content = $content -replace '(?s)<div class="nav-right">', "<div class=`"nav-right`">`n                <div id=`"google_translate_element`"></div>"
         $updated = $true
    }
    # 4. Special case for admin_login.html (absolute theme toggle)
    elseif ($content -match '<div class="theme-toggle" style="position: absolute;' -and $content -notmatch 'id="google_translate_element"') {
         $content = $content -replace '(?s)<div class="theme-toggle"', '<div id="google_translate_element" style="position: absolute; top: 20px; right: 80px; z-index: 1000;"></div><div class="theme-toggle"'
         $updated = $true
    }

    # 5. Add script if missing
    if ($content -notmatch 'src="js/translation.js"') {
        $replacement = "    <script src=`"js/translation.js`"></script>`n</body>"
        $content = $content -replace '</body>', $replacement
        $updated = $true
    }

    if ($updated) {
        Set-Content -Path $file.FullName -Value $content -Encoding UTF8
        Write-Host "Updated $($file.Name)"
    }
}
