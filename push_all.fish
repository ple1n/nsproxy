#!/usr/bin/env fish

# Push all submodules recursively
for submodule in (git submodule status --recursive | awk '{ print $2 }')
    echo "Pushing submodule: $submodule"
    # git submodule update --remote --merge $submodule
    git -C $submodule push
end

# Finally, push the main repository itself
echo "Pushing main repository"
git push
