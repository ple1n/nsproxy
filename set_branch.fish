#!/usr/bin/env fish

# Initialize submodules if necessary
git submodule update --init --recursive

# Iterate over each submodule in the status
for submodule in (git submodule status --recursive)
    # Extract the path and commit hash
    set path (echo $submodule | awk '{print $2}')
    
    # Get the branch configured in .gitmodules for this submodule
    set branch (git config --file .gitmodules submodule."$path".branch)
    
    if test -z "$branch"
        echo "No branch configured for $path, skipping..."
        continue
    end
    
    # Navigate to the submodule directory and check out the branch
    cd $path
    echo "Checking out branch '$branch' for submodule $path"
    git checkout $branch
    cd - > /dev/null
end

echo "All submodules have been checked out to their configured branches."
