Contributing to Aleph
======================

WIP


Dealing with requirements
====================================
Whenever new pip dependencies are added, regenerate the requirements.txt file with pip-chill instead of pip freeze
    pip-chill --no-versions > requirements.txt


Keeping the version file up to date
====================================
    cp git-create-revisioninfo-hook.sh .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
