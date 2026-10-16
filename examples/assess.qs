# assess.qs — a runnable example of the shared QYVORA scripting engine driving
# timbuktu's offline forensics pipeline.
#
#     timbuktu script run examples/assess.qs
#
# timbuktu is offline and deterministic, so this needs no case setup: with no
# case file configured the binding runs the built-in simulation.

# Select the deterministic simulation (the default when no case is set).
set assess.sim -> "true"

# Run the full pipeline. Capability ids such as "forensics.artifacts" run the
# pipeline up to and including that stage.
run assess

# Read live properties from the completed run via $(...).
echo -> "target   = $(target.name)"
echo -> "assets   = $(result.assets)"
echo -> "findings = $(result.findings)"
echo -> "score    = $(result.score) ($(result.level))"

# Show capability metadata and write a Markdown report artifact.
show forensics.acquisition
report -> "timbuktu-report"

echo -> "done"
