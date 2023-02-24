# Git

## Branches
List branches
```
git branch --list
```

New branch for feature
```
git checkout -b feature_name
```

```
$ git checkout -b hotfix
do the fix in the hotfix, and test.
$ git checkout master
$ git merge hotfix
$ git branch -d hotfix

```


Other commands
```
-d
--delete
Delete a branch. The branch must be fully merged in its upstream branch, or in HEAD if no upstream was set with --track or --set-upstream-to.

-D
Shortcut for --delete --force.

--create-reflog
Create the branch’s reflog. This activates recording of all changes made to the branch ref, enabling use of date based sha1 expressions such as "<branchname>@{yesterday}". Note that in non-bare repositories, reflogs are usually enabled by default by the core.logAllRefUpdates config option. The negated form --no-create-reflog only overrides an earlier --create-reflog, but currently does not negate the setting of core.logAllRefUpdates.

-f
--force
Reset <branchname> to <startpoint>, even if <branchname> exists already. Without -f, git branch refuses to change an existing branch. In combination with -d (or --delete), allow deleting the branch irrespective of its merged status, or whether it even points to a valid commit. In combination with -m (or --move), allow renaming the branch even if the new branch name already exists, the same applies for -c (or --copy).

-m
--move
Move/rename a branch, together with its config and reflog.

-M
Shortcut for --move --force.

-c
--copy
Copy a branch, together with its config and reflog.

-C
Shortcut for --copy --force.
```
