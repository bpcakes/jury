#!/usr/bin/env bash
set -euo pipefail

WORKFLOW_DIR="${1:-.github/workflows}"
REPO_ROOT="${2:-$(cd -- "$WORKFLOW_DIR/../.." && pwd)}"

if ! command -v ruby >/dev/null 2>&1; then
  echo "Ruby with its standard YAML parser is required to verify action pins." >&2
  exit 1
fi

ruby - "$WORKFLOW_DIR" "$REPO_ROOT" <<'RUBY'
require "yaml"

workflow_dir = ARGV.fetch(0)
repo_root = File.realpath(ARGV.fetch(1))
action_pattern = %r{\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.@/-]+)?@[0-9a-f]{40}\z}
docker_pattern = %r{\Adocker://[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}\z}
status = 0
queue = Dir.glob(File.join(workflow_dir, "**", "*.{yml,yaml}")).sort
queued = queue.to_h { |path| [File.expand_path(path), true] }
visited_files = {}

enqueue_local = lambda do |reference, source_path|
  target = File.expand_path(reference, repo_root)
  unless target == repo_root || target.start_with?(repo_root + File::SEPARATOR)
    warn "Local action escapes the repository in #{source_path}: #{reference.inspect}"
    status = 1
    next
  end

  if File.directory?(target)
    candidates = %w[action.yml action.yaml].map { |name| File.join(target, name) }.select { |path| File.file?(path) }
    if candidates.length != 1
      warn "Local action must contain exactly one action.yml or action.yaml in #{source_path}: #{reference.inspect}"
      status = 1
      next
    end
    target = candidates.first
  elsif !File.file?(target) || !target.match?(/\.ya?ml\z/)
    warn "Local reusable workflow does not resolve to YAML in #{source_path}: #{reference.inspect}"
    status = 1
    next
  end

  expanded = File.expand_path(target)
  unless queued[expanded] || visited_files[expanded]
    queued[expanded] = true
    queue << expanded
  end
end

visit = lambda do |value, path, seen|
  case value
  when Hash
    next if seen[value.object_id]
    seen[value.object_id] = true
    value.each do |key, child|
      if key == "uses"
        if !child.is_a?(String)
          warn "Action reference must be a string in #{path}: #{child.inspect}"
          status = 1
        elsif child.start_with?("./")
          enqueue_local.call(child, path)
        elsif !(child.match?(action_pattern) || child.match?(docker_pattern))
          warn "Third-party action is not pinned to a full commit SHA in #{path}: #{child.inspect}"
          status = 1
        end
      end
      visit.call(child, path, seen)
    end
  when Array
    next if seen[value.object_id]
    seen[value.object_id] = true
    value.each { |child| visit.call(child, path, seen) }
  end
end

until queue.empty?
  path = queue.shift
  begin
    resolved_path = File.realpath(path)
    unless resolved_path == repo_root || resolved_path.start_with?(repo_root + File::SEPARATOR)
      warn "Workflow or local action escapes the repository: #{path}"
      status = 1
      next
    end
    if visited_files[resolved_path]
      next
    end
    visited_files[resolved_path] = true
    source = File.read(path)
    parsed_stream = Psych.parse_stream(source)
    if parsed_stream.children.length != 1
      warn "Cannot safely parse workflow #{path}: exactly one YAML document is required"
      status = 1
      next
    end
    document = YAML.safe_load(source, aliases: true)
    visit.call(document, path, {})
  rescue Psych::Exception, SystemCallError => error
    warn "Cannot safely parse workflow #{path}: #{error.message}"
    status = 1
  end
end

exit status
RUBY
