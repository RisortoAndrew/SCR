# Enter directly in term:
```powershell
$basePath = Get-Location; $outputFile = "path_num_extensions.txt"; Clear-Content -Path $outputFile -ErrorAction SilentlyContinue; Get-ChildItem -Directory | ForEach-Object { "+++++++++++++++++++++++++++++" | Out-File -FilePath $outputFile -Append; $_.Name | Out-File -FilePath $outputFile -Append; "+++++++++++++++++++++++++++++" | Out-File -FilePath $outputFile -Append; "`n" | Out-File -FilePath $outputFile -Append; Get-ChildItem -Path $_.FullName -Recurse -File | Group-Object { $_.DirectoryName } | ForEach-Object { $path = $_.Name.Substring($basePath.Path.Length + 1); $files = $_.Group; "Path: $path" | Out-File -FilePath $outputFile -Append; "Files contained:" | Out-File -FilePath $outputFile -Append; $files | Group-Object { $_.Extension } | ForEach-Object { $extension = if ($_.Name -eq "") {"No extension"} else { $_.Name }; $count = $_.Count; "$extension files: $count" | Out-File -FilePath $outputFile -Append }; "`n==============================`n" | Out-File -FilePath $outputFile -Append } }
``` 


# .ps1 script to do the same:


```powershell
# PowerShell script to generate a report of file types and counts in each directory

$basePath = Get-Location
$outputFile = "path_num_extensions.txt"

# Clear the output file if it exists
Clear-Content -Path $outputFile -ErrorAction SilentlyContinue

# Get top-level directories
$topLevelDirs = Get-ChildItem -Directory

foreach ($topDir in $topLevelDirs) {
    # Write the banner for the top-level directory
    "+++++++++++++++++++++++++++++" | Out-File -FilePath $outputFile -Append
    $topDir.Name | Out-File -FilePath $outputFile -Append
    "+++++++++++++++++++++++++++++" | Out-File -FilePath $outputFile -Append
    "`n" | Out-File -FilePath $outputFile -Append

    # Process files under the current top-level directory
    Get-ChildItem -Path $topDir.FullName -Recurse -File | Group-Object { $_.DirectoryName } | ForEach-Object {
        $path = $_.Name.Substring($basePath.Path.Length + 1)
        $files = $_.Group

        # Write to the output file
        "Path: $path" | Out-File -FilePath $outputFile -Append
        "Files contained:" | Out-File -FilePath $outputFile -Append

        $files | Group-Object { $_.Extension } | ForEach-Object {
            $extension = if ($_.Name -eq "") {"No extension"} else { $_.Name }
            $count = $_.Count
            "$extension files: $count" | Out-File -FilePath $outputFile -Append
        }

        "`n==============================`n" | Out-File -FilePath $outputFile -Append
    }
}
```
