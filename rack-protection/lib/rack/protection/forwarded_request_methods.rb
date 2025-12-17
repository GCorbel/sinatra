# frozen_string_literal: true

module Rack
  module Protection
    # Extensions to Rack::Request to support forwarded request detection.
    # These methods are backported from Rack 3.2.4 for CVE mitigation.

    module ForwardedRequestMethods
      # Took from https://github.com/rack/rack/blob/v3.2.4/lib/rack/request.rb#L398
      def forwarded_authority
        [:forwarded, :x_forwarded].each do |type|
          case type
          when :forwarded
            if forwarded = get_http_forwarded(:host)
              return forwarded.last
            end
          when :x_forwarded
            if (value = get_header(Rack::Request::HTTP_X_FORWARDED_HOST)) && (x_forwarded_host = split_header(value).last)
              return wrap_ipv6(x_forwarded_host)
            end
          end
        end

        nil
      end

      # Took from https://github.com/rack/rack/blob/v3.2.4/lib/rack/request.rb#L665-L667
      # Get an array of values set in the RFC 7239 `Forwarded` request header.
      def get_http_forwarded(token)
        forwarded_values(get_header('HTTP_FORWARDED'))&.[](token)
      end

      # Took from https://github.com/rack/rack/blob/v3.2.4/lib/rack/utils.rb
      def forwarded_values(forwarded_header)
        return nil unless forwarded_header
        forwarded_header = forwarded_header.to_s.gsub("\n", ";")

        forwarded_header.split(';').each_with_object({}) do |field, values|
          field.split(',').each do |pair|
            pair = pair.split('=').map(&:strip).join('=')
            return nil unless pair =~ /\A(by|for|host|proto)="?([^"]+)"?\Z/i
            (values[$1.downcase.to_sym] ||= []) << $2
          end
        end
      end
    end
  end
end

